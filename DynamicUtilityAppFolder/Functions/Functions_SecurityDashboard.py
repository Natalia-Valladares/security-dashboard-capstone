#title: 'Security Dashboard'
#btn: 'Security Findings'
#btn: 'Table Risk Scores'
#btn: 'Database Risk Scores'
#btn: 'Device Health Status'

"""
SecurityDashboardModule.py

DynamicUtilityApp-compatible wrapper that reads directly from
security_dashboard_results.db (SQLite) using plain SQL.
"""

from datetime import datetime
import os

from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError


class SecurityDashboardUtility:
    """
    This class is instantiated by DynamicUtilityApp.

    The GUI:
    - Reads the #title and #btn comments above.
    - Loads this class as the first class in the module.
    - Calls get_<button_name>() when you click a button.

    Button names -> functions:
      'Security Findings'      -> get_security_findings()
      'Table Risk Scores'      -> get_table_risk_scores()
      'Database Risk Scores'   -> get_database_risk_scores()
      'Device Health Status'   -> get_device_health_status()
    """

    def __init__(self):
        # MUST match RESULTS_DB_URL in security_dashboard_backend.py
        ROOT_DIR = os.path.dirname(os.path.dirname(__file__))
        DB_PATH = os.path.join(ROOT_DIR, "security_dashboard_results.db")

        db_url = f"sqlite:///{DB_PATH.replace(os.sep, '/')}"
        self.RESULTS_DB_URL = db_url

        self.engine = create_engine(self.RESULTS_DB_URL)

    # --------------- Security Findings -----------------
    def get_security_findings(self):
        cols = (
            "ID",
            "Source DB",
            "Schema",
            "Table",
            "Column",
            "Type",
            "Severity",
            "Description",
            "Scanner",
            "Created At",
        )
        try:
            with self.engine.connect() as conn:
                result = conn.execute(
                    text(
                        """
                        SELECT
                            id,
                            source_db,
                            schema_name,
                            table_name,
                            column_name,
                            finding_type,
                            severity,
                            description,
                            scanner_name,
                            created_at
                        FROM security_findings
                        ORDER BY created_at DESC
                        LIMIT 500
                        """
                    )
                )
                rows = [tuple(r) for r in result]
            return cols, rows
        except SQLAlchemyError as e:
            return ("Message",), [(f"DB error loading findings: {e}",)]

    # --------------- Table Risk Scores -----------------
    def get_table_risk_scores(self):
        cols = (
            "ID",
            "Source DB",
            "Schema",
            "Table",
            "Risk Score",
            "Risk Level",
            "Last Calculated",
        )
        try:
            with self.engine.connect() as conn:
                result = conn.execute(
                    text(
                        """
                        SELECT
                            id,
                            source_db,
                            schema_name,
                            table_name,
                            risk_score,
                            risk_level,
                            last_calculated_at
                        FROM table_risk_scores
                        ORDER BY risk_score DESC
                        LIMIT 500
                        """
                    )
                )
                rows = [tuple(r) for r in result]
            return cols, rows
        except SQLAlchemyError as e:
            return ("Message",), [(f"DB error loading table risk scores: {e}",)]

    # --------------- Database Risk Scores --------------
    def get_database_risk_scores(self):
        cols = (
            "ID",
            "Source DB",
            "Total Risk Score",
            "Risk Level",
            "Last Calculated",
        )
        try:
            with self.engine.connect() as conn:
                result = conn.execute(
                    text(
                        """
                        SELECT
                            id,
                            source_db,
                            risk_score,
                            risk_level,
                            last_calculated_at
                        FROM database_risk_scores
                        ORDER BY risk_score DESC
                        """
                    )
                )
                rows = [tuple(r) for r in result]
            return cols, rows
        except SQLAlchemyError as e:
            return ("Message",), [(f"DB error loading database risk scores: {e}",)]

    # --------------- Device Health Status --------------
    def get_device_health_status(self):
        # If you haven't run ingest_and_normalize_data yet,
        # this table may be empty, that's OK.
        cols = (
            "Device ID",
            "Alarm Count",
            "HighFlow Alarms",
            "Voltage (VDC)",
            "Avg Signal",
            "Comm Errors",
            "Risk Score",
            "Last Seen",
        )
        try:
            with self.engine.connect() as conn:
                result = conn.execute(
                    text(
                        """
                        SELECT
                            device_id,
                            alarm_count,
                            highflow_alarm_count,
                            voltage_vdc,
                            avg_signal_strength,
                            comm_error_count,
                            risk_score,
                            last_seen
                        FROM device_status
                        ORDER BY risk_score DESC
                        LIMIT 500
                        """
                    )
                )
                rows = [tuple(r) for r in result]
            return cols, rows
        except SQLAlchemyError as e:
            return ("Message",), [(f"DB error loading device health: {e}",)]
