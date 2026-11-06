import unittest
from datetime import datetime, timezone, timedelta
import traffic_anomaly_engine as tae

class TestTrafficAnomalyEngine(unittest.TestCase):

    def test_robust_baseline_calculation(self):
        # Normal distribution around 20 MB with some outliers
        samples = [18 * 1024 * 1024, 20 * 1024 * 1024, 21 * 1024 * 1024, 19 * 1024 * 1024, 150 * 1024 * 1024]
        res = tae.calculate_robust_baseline(samples)
        # Median should not be skewed by the 150MB outlier
        self.assertAlmostEqual(res["median"], 20 * 1024 * 1024, delta=1024*1024)
        self.assertTrue(res["mad"] > 0)

    def test_learning_period_max_severity_low(self):
        # 3 days of historical samples
        now = datetime.now(timezone.utc)
        history = []
        for d in range(1, 4):
            day_time = now - timedelta(days=d)
            history.append({
                "recorded_at": day_time,
                "delta_tx_bytes": 10 * 1024 * 1024,
                "hour_of_day": now.hour
            })
        
        # Test large spike during learning period
        res = tae.detect_traffic_anomaly(
            server_id=1,
            delta_tx=120 * 1024 * 1024, # 120 MB
            delta_rx=0,
            history_samples=history,
            active_conns=[{"remote_ip": "8.8.8.8", "remote_port": 4444}],
            current_time=now
        )
        self.assertTrue(res["is_anomaly"])
        self.assertEqual(res["severity"], "low")
        self.assertIn("baseline building (3 of 7 days)", res["message"])

    def test_single_window_is_low(self):
        # 7 full days of history
        now = datetime.now(timezone.utc)
        history = []
        for d in range(1, 8):
            history.append({
                "recorded_at": now - timedelta(days=d),
                "delta_tx_bytes": 15 * 1024 * 1024,
                "hour_of_day": now.hour
            })

        tae._ANOMALY_TRACKER.clear() # clear state
        res = tae.detect_traffic_anomaly(
            server_id=2,
            delta_tx=150 * 1024 * 1024, # 150 MB (10x baseline)
            delta_rx=0,
            history_samples=history,
            active_conns=[{"remote_ip": "1.2.3.4", "remote_port": 4444}],
            current_time=now
        )
        # Single window must be LOW per Rule 4
        self.assertTrue(res["is_anomaly"])
        self.assertEqual(res["severity"], "low")
        self.assertIn("single window: 1 of 2 required", res["message"])

    def test_sustain_with_signals_escalates(self):
        now = datetime.now(timezone.utc)
        history = []
        for d in range(1, 8):
            history.append({
                "recorded_at": now - timedelta(days=d),
                "delta_tx_bytes": 15 * 1024 * 1024,
                "hour_of_day": now.hour
            })

        tae._ANOMALY_TRACKER.clear()
        # Window 1
        tae.detect_traffic_anomaly(
            server_id=3, delta_tx=150 * 1024 * 1024, delta_rx=0,
            history_samples=history, active_conns=[], current_time=now
        )
        # Window 2: Sustained, with external IP and suspicious port
        res = tae.detect_traffic_anomaly(
            server_id=3, delta_tx=160 * 1024 * 1024, delta_rx=0,
            history_samples=history,
            active_conns=[
                {"remote_ip": "198.51.100.25", "remote_port": 4444, "process": "nc"}
            ],
            current_time=now + timedelta(seconds=30)
        )
        self.assertTrue(res["is_anomaly"])
        self.assertIn(res["severity"], ["high", "critical"])
        self.assertEqual(res["consecutive_windows"], 2)
        self.assertTrue(len(res["signals"]) >= 1)

if __name__ == '__main__':
    unittest.main()
