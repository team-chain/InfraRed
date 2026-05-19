"""
UEBA Isolation Forest 모델.
v4.0 설계서 §7.3 참조.
테넌트별 독립 모델, S3 저장/로드.

v7.0 추가:
- Cold Start 방어: 학습 데이터 부족 시 임계값 하향 (더 민감하게)
- Drift Detection: 4주에 걸친 점진적 베이스라인 조작 탐지
"""
from __future__ import annotations

import io
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    import pandas as pd
    import joblib
    import numpy as np
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logger.warning("scikit-learn not available. UEBA model disabled.")

import boto3
from app.config import get_settings


# ---------------------------------------------------------------------------
# v7.0: DriftReport 데이터클래스
# ---------------------------------------------------------------------------

@dataclass
class DriftReport:
    """UEBA Drift 탐지 결과."""
    is_drifting: bool
    drift_score: float
    affected_features: list[str] = field(default_factory=list)
    rule_id: str = "UEBA-DRIFT-001"
    detected_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "is_drifting": self.is_drifting,
            "drift_score": self.drift_score,
            "affected_features": self.affected_features,
            "rule_id": self.rule_id,
            "detected_at": self.detected_at,
        }


# ---------------------------------------------------------------------------
# UEBAModel
# ---------------------------------------------------------------------------

class UEBAModel:
    """
    테넌트별 독립 Isolation Forest 모델.
    최초 7일: Silent Mode (학습만)
    8일째+: 탐지 활성화

    v7.0 Cold Start 방어:
    - 모델 생성일 기준 7일 미만이면 Cold Start 모드
    - Cold Start 중에는 임계값을 30% 낮춰 더 민감하게 탐지

    v7.0 Drift Detection:
    - 최근 N일간 프로파일 평균과 학습 시점 평균 비교
    - 차이가 threshold(0.3 std) 초과 시 UEBA-DRIFT-001 경고
    """

    MODEL_PATH_TEMPLATE = "ueba-models/{tenant_id}/isolation_forest.joblib"

    # v7.0 Cold Start 상수
    COLD_START_DAYS = 7
    COLD_START_THRESHOLD_MULTIPLIER = 0.7  # 임계값 30% 하향 → 더 민감

    # v7.0 Drift Detection 상수
    DRIFT_THRESHOLD_STD = 0.3   # 표준편차 0.3 초과 시 drift 판정
    DRIFT_WINDOW_DAYS = 28      # 4주 윈도우

    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id
        self.model = None
        self.scaler = None
        self._trained = False
        self._created_at: Optional[float] = None   # Unix timestamp (모델 최초 생성 시각)
        self._train_feature_means: Optional[list[float]] = None   # 학습 시점 특성 평균
        self._train_feature_stds: Optional[list[float]] = None    # 학습 시점 특성 표준편차
        settings = get_settings()

        if not SKLEARN_AVAILABLE:
            return

        kwargs = {"region_name": settings.s3_region}
        if settings.aws_access_key_id:
            kwargs["aws_access_key_id"] = settings.aws_access_key_id
            kwargs["aws_secret_access_key"] = settings.aws_secret_access_key
        self.s3 = boto3.client("s3", **kwargs)
        self.bucket = settings.ueba_model_bucket
        self._load_or_init()

    def _load_or_init(self):
        if not SKLEARN_AVAILABLE:
            return
        try:
            key = self.MODEL_PATH_TEMPLATE.format(tenant_id=self.tenant_id)
            settings = get_settings()
            obj = self.s3.get_object(Bucket=self.bucket, Key=key)
            buffer = io.BytesIO(obj["Body"].read())
            saved = joblib.load(buffer)
            self.model = saved["model"]
            self.scaler = saved["scaler"]
            self._trained = True
            # v7.0: 메타데이터 로드
            self._created_at = saved.get("created_at")
            self._train_feature_means = saved.get("train_feature_means")
            self._train_feature_stds = saved.get("train_feature_stds")
            logger.info(f"UEBA model loaded for tenant {self.tenant_id}")
        except Exception:
            self.model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
            self.scaler = StandardScaler()
            self._trained = False
            self._created_at = None

    def train(self, profiles: list) -> bool:
        """주 1회 재학습"""
        if not SKLEARN_AVAILABLE or len(profiles) < 10:
            return False
        try:
            X = [p.to_feature_vector() for p in profiles]
            import numpy as np
            X_arr = np.array(X, dtype=float)
            X_scaled = self.scaler.fit_transform(X_arr)
            self.model.fit(X_scaled)
            self._trained = True

            # v7.0: 학습 시점 통계 저장 (Drift Detection 기준값)
            self._train_feature_means = X_arr.mean(axis=0).tolist()
            self._train_feature_stds = X_arr.std(axis=0).tolist()

            # created_at이 없으면 최초 학습 시각 기록
            if self._created_at is None:
                self._created_at = time.time()

            self._save_model()
            logger.info(f"UEBA model trained: {len(profiles)} profiles, tenant={self.tenant_id}")
            return True
        except Exception as e:
            logger.error(f"UEBA training failed: {e}")
            return False

    def _save_model(self):
        if not SKLEARN_AVAILABLE:
            return
        try:
            key = self.MODEL_PATH_TEMPLATE.format(tenant_id=self.tenant_id)
            buffer = io.BytesIO()
            joblib.dump({
                "model": self.model,
                "scaler": self.scaler,
                # v7.0: 메타데이터 포함
                "created_at": self._created_at,
                "train_feature_means": self._train_feature_means,
                "train_feature_stds": self._train_feature_stds,
            }, buffer)
            settings = get_settings()
            self.s3.put_object(Bucket=self.bucket, Key=key, Body=buffer.getvalue())
        except Exception as e:
            logger.warning(f"UEBA model save failed: {e}")

    def score(self, profile) -> float:
        """
        이상도 점수: -1.0 (완전 이상) ~ 1.0 (완전 정상).
        모델 미학습 시 0.0 반환.
        """
        if not SKLEARN_AVAILABLE or not self._trained:
            return 0.0
        try:
            import numpy as np
            X = np.array([profile.to_feature_vector()], dtype=float)
            X_scaled = self.scaler.transform(X)
            return float(self.model.score_samples(X_scaled)[0])
        except Exception as e:
            logger.error(f"UEBA scoring failed: {e}")
            return 0.0

    # ------------------------------------------------------------------
    # v7.0: Cold Start 방어
    # ------------------------------------------------------------------

    def is_cold_start(self) -> bool:
        """S3에 저장된 모델 생성일 기준 7일 미만이면 Cold Start 상태."""
        if self._created_at is None:
            # 아직 학습된 모델이 없으면 Cold Start
            return True
        elapsed_days = (time.time() - self._created_at) / 86400
        return elapsed_days < self.COLD_START_DAYS

    def score_with_cold_start(self, profile) -> tuple[float, bool]:
        """Cold Start 감지 후 점수 보정.

        Cold Start 중이면 score를 COLD_START_THRESHOLD_MULTIPLIER 배 조정
        (더 민감하게: 낮은 점수도 이상으로 판단).

        Returns:
            (adjusted_score, is_cold_start)
        """
        raw_score = self.score(profile)
        cold = self.is_cold_start()

        if cold and raw_score < 0:
            # 음수 점수(이상)를 더 강조: MULTIPLIER < 1.0 이므로 더 음수쪽으로
            adjusted = raw_score / self.COLD_START_THRESHOLD_MULTIPLIER
            # 범위 클램핑 [-1.0, 0.0]
            adjusted = max(-1.0, adjusted)
            return adjusted, True

        return raw_score, cold

    # ------------------------------------------------------------------
    # v7.0: Drift Detection
    # ------------------------------------------------------------------

    def detect_drift(
        self,
        recent_profiles: list,
        window_days: int = DRIFT_WINDOW_DAYS,
    ) -> DriftReport:
        """4주에 걸친 점진적 베이스라인 조작 탐지.

        최근 N일간 프로파일의 평균 특성 벡터와 학습 시점 평균을 비교한다.
        차이가 threshold(0.3 std) 초과 시 UEBA-DRIFT-001 경고 반환.

        Args:
            recent_profiles: 최근 window_days 동안의 UserBehaviorFeatures 목록
            window_days: 비교 윈도우 (기본 28일)

        Returns:
            DriftReport
        """
        if not SKLEARN_AVAILABLE:
            return DriftReport(is_drifting=False, drift_score=0.0)

        if not self._train_feature_means or not self._train_feature_stds:
            logger.debug("No training baseline available for drift detection, tenant=%s", self.tenant_id)
            return DriftReport(is_drifting=False, drift_score=0.0)

        if not recent_profiles:
            return DriftReport(is_drifting=False, drift_score=0.0)

        try:
            import numpy as np

            X_recent = np.array(
                [p.to_feature_vector() for p in recent_profiles],
                dtype=float,
            )
            recent_means = X_recent.mean(axis=0)

            train_means = np.array(self._train_feature_means, dtype=float)
            train_stds = np.array(self._train_feature_stds, dtype=float)

            # 특성 이름 (UserBehaviorFeatures.to_feature_vector() 순서와 동일해야 함)
            feature_names = [
                "login_hour_mean", "login_hour_std", "login_count",
                "off_hours_login_count", "unique_source_ips", "unique_countries",
                "new_ip_ratio", "failed_login_count", "success_after_failure",
                "commands_executed", "sudo_commands", "files_accessed",
                "session_duration_mean", "concurrent_sessions",
            ]

            # 표준화된 차이 계산
            # std가 0이면 나누기 방지
            safe_stds = np.where(train_stds > 1e-9, train_stds, 1.0)
            normalized_diff = np.abs(recent_means - train_means) / safe_stds

            # 전체 drift score: 평균 정규화 차이
            drift_score = float(normalized_diff.mean())

            # threshold 초과한 특성 목록
            affected_features: list[str] = []
            for i, diff in enumerate(normalized_diff):
                if diff > self.DRIFT_THRESHOLD_STD:
                    name = feature_names[i] if i < len(feature_names) else f"feature_{i}"
                    affected_features.append(name)

            is_drifting = drift_score > self.DRIFT_THRESHOLD_STD

            if is_drifting:
                logger.warning(
                    "UEBA drift detected: tenant=%s, drift_score=%.3f, affected=%s",
                    self.tenant_id, drift_score, affected_features,
                )

            return DriftReport(
                is_drifting=is_drifting,
                drift_score=drift_score,
                affected_features=affected_features,
            )

        except Exception as e:
            logger.error(f"UEBA drift detection failed: {e}")
            return DriftReport(is_drifting=False, drift_score=0.0)

    @staticmethod
    def to_novelty_bonus(score: float) -> float:
        """UEBA 점수 → Detection Confidence novelty_bonus 변환"""
        if score < -0.7:
            return 0.20
        elif score < -0.5:
            return 0.12
        elif score < -0.3:
            return 0.05
        return 0.0


# 테넌트별 모델 캐시
_model_cache: dict[str, UEBAModel] = {}


def get_ueba_model(tenant_id: str) -> UEBAModel:
    if tenant_id not in _model_cache:
        _model_cache[tenant_id] = UEBAModel(tenant_id)
    return _model_cache[tenant_id]
