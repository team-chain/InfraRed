"""
UEBA Autoencoder 기반 이상탐지 — v4.0 §7 Phase 2.
numpy만 사용 (tensorflow/pytorch 불필요).
재구성 오차가 임계값 초과 시 이상으로 판정.
최소 30일 데이터 필요.
"""
from __future__ import annotations

import io
import logging
import math

import numpy as np

from app.workers.ueba.features import UserBehaviorFeatures

logger = logging.getLogger(__name__)

try:
    import boto3
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False


def _relu(x: np.ndarray) -> np.ndarray:
    return np.maximum(0, x)

def _sigmoid(x: np.ndarray) -> np.ndarray:
    return 1 / (1 + np.exp(-np.clip(x, -500, 500)))


class AutoencoderModel:
    """
    3층 오토인코더 (14 → 7 → 3 → 7 → 14).
    numpy 경사하강법으로 학습.
    S3에 가중치 저장/로드.
    30일+ 데이터 있을 때 Isolation Forest 대체.
    """
    INPUT_DIM = 14
    HIDDEN_DIM = 7
    LATENT_DIM = 3
    LEARNING_RATE = 0.001
    EPOCHS = 500
    BATCH_SIZE = 32
    MIN_TRAINING_DAYS = 30
    MODEL_PATH_TEMPLATE = "ueba-models/{tenant_id}/autoencoder.npz"

    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id
        self.threshold: float = 0.1
        self._trained = False
        # 가중치 초기화 (Xavier)
        self._init_weights()

    def _init_weights(self):
        scale1 = math.sqrt(2.0 / self.INPUT_DIM)
        scale2 = math.sqrt(2.0 / self.HIDDEN_DIM)
        scale3 = math.sqrt(2.0 / self.LATENT_DIM)
        self.W1 = np.random.randn(self.INPUT_DIM, self.HIDDEN_DIM) * scale1
        self.b1 = np.zeros(self.HIDDEN_DIM)
        self.W2 = np.random.randn(self.HIDDEN_DIM, self.LATENT_DIM) * scale2
        self.b2 = np.zeros(self.LATENT_DIM)
        self.W3 = np.random.randn(self.LATENT_DIM, self.HIDDEN_DIM) * scale3
        self.b3 = np.zeros(self.HIDDEN_DIM)
        self.W4 = np.random.randn(self.HIDDEN_DIM, self.INPUT_DIM) * scale2
        self.b4 = np.zeros(self.INPUT_DIM)
        self.mean_ = np.zeros(self.INPUT_DIM)
        self.std_ = np.ones(self.INPUT_DIM)

    def _forward(self, X: np.ndarray):
        h1 = _relu(X @ self.W1 + self.b1)
        latent = _relu(h1 @ self.W2 + self.b2)
        h3 = _relu(latent @ self.W3 + self.b3)
        out = _sigmoid(h3 @ self.W4 + self.b4)
        return h1, latent, h3, out

    def _normalize(self, X: np.ndarray) -> np.ndarray:
        return (X - self.mean_) / (self.std_ + 1e-8)

    def train(self, profiles: list[UserBehaviorFeatures]) -> bool:
        if len(profiles) < self.MIN_TRAINING_DAYS:
            logger.info(f"Not enough data for autoencoder: {len(profiles)} < {self.MIN_TRAINING_DAYS}")
            return False

        X_raw = np.array([p.to_feature_vector() for p in profiles], dtype=float)
        X_raw = np.nan_to_num(X_raw, nan=0.0)
        self.mean_ = X_raw.mean(axis=0)
        self.std_ = X_raw.std(axis=0)
        X = self._normalize(X_raw)
        X = np.clip(X, 0, 1)  # sigmoid 출력과 동일 범위

        lr = self.LEARNING_RATE
        n = len(X)

        for epoch in range(self.EPOCHS):
            idx = np.random.permutation(n)
            for start in range(0, n, self.BATCH_SIZE):
                batch = X[idx[start:start + self.BATCH_SIZE]]
                h1, latent, h3, out = self._forward(batch)

                # 재구성 오차 (MSE)
                loss = np.mean((batch - out) ** 2)

                # 역전파 (간단한 chain rule)
                d_out = 2 * (out - batch) / len(batch)
                d_out *= out * (1 - out)  # sigmoid 미분

                dW4 = h3.T @ d_out
                db4 = d_out.sum(axis=0)
                d_h3 = d_out @ self.W4.T
                d_h3 *= (h3 > 0)  # relu 미분

                dW3 = latent.T @ d_h3
                db3 = d_h3.sum(axis=0)
                d_latent = d_h3 @ self.W3.T
                d_latent *= (latent > 0)

                dW2 = h1.T @ d_latent
                db2 = d_latent.sum(axis=0)
                d_h1 = d_latent @ self.W2.T
                d_h1 *= (h1 > 0)

                dW1 = batch.T @ d_h1
                db1 = d_h1.sum(axis=0)

                # 가중치 업데이트
                self.W1 -= lr * dW1
                self.b1 -= lr * db1
                self.W2 -= lr * dW2
                self.b2 -= lr * db2
                self.W3 -= lr * dW3
                self.b3 -= lr * db3
                self.W4 -= lr * dW4
                self.b4 -= lr * db4

            if epoch % 100 == 0:
                logger.debug(f"Autoencoder epoch {epoch}, loss={loss:.4f}")

        # 임계값: 훈련 데이터 재구성 오차 95th percentile
        errors = self._reconstruction_errors(X)
        self.threshold = float(np.percentile(errors, 95))
        self._trained = True
        self._save_to_s3()
        return True

    def _reconstruction_errors(self, X: np.ndarray) -> np.ndarray:
        _, _, _, out = self._forward(X)
        return np.mean((X - out) ** 2, axis=1)

    def score(self, profile: UserBehaviorFeatures) -> float:
        """재구성 오차 반환. 높을수록 이상."""
        x = np.array([profile.to_feature_vector()], dtype=float)
        x = np.nan_to_num(x, nan=0.0)
        x = self._normalize(x)
        x = np.clip(x, 0, 1)
        errors = self._reconstruction_errors(x)
        return float(errors[0])

    def is_anomalous(self, profile: UserBehaviorFeatures) -> bool:
        return self.score(profile) > self.threshold

    def to_novelty_bonus(self, profile: UserBehaviorFeatures) -> float:
        error = self.score(profile)
        ratio = error / (self.threshold + 1e-8)
        if ratio > 3.0:
            return 0.20
        elif ratio > 2.0:
            return 0.12
        elif ratio > 1.5:
            return 0.05
        return 0.0

    def _save_to_s3(self):
        if not BOTO3_AVAILABLE:
            return
        try:
            from app.config import get_settings
            settings = get_settings()
            s3 = boto3.client("s3", region_name=settings.s3_region)
            buf = io.BytesIO()
            np.savez(buf, W1=self.W1, b1=self.b1, W2=self.W2, b2=self.b2,
                     W3=self.W3, b3=self.b3, W4=self.W4, b4=self.b4,
                     mean=self.mean_, std=self.std_, threshold=[self.threshold])
            buf.seek(0)
            key = self.MODEL_PATH_TEMPLATE.format(tenant_id=self.tenant_id)
            s3.put_object(Bucket=settings.ueba_model_bucket, Key=key, Body=buf.getvalue())
            logger.info(f"Autoencoder saved to S3: {key}")
        except Exception as e:
            logger.warning(f"S3 save failed: {e}")

    def _load_from_s3(self) -> bool:
        if not BOTO3_AVAILABLE:
            return False
        try:
            from app.config import get_settings
            settings = get_settings()
            s3 = boto3.client("s3", region_name=settings.s3_region)
            key = self.MODEL_PATH_TEMPLATE.format(tenant_id=self.tenant_id)
            obj = s3.get_object(Bucket=settings.ueba_model_bucket, Key=key)
            data = np.load(io.BytesIO(obj["Body"].read()))
            self.W1, self.b1 = data["W1"], data["b1"]
            self.W2, self.b2 = data["W2"], data["b2"]
            self.W3, self.b3 = data["W3"], data["b3"]
            self.W4, self.b4 = data["W4"], data["b4"]
            self.mean_, self.std_ = data["mean"], data["std"]
            self.threshold = float(data["threshold"][0])
            self._trained = True
            return True
        except Exception:
            return False
