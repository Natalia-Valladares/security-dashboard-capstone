"""
Security Dashboard Backend (single-file version)

All backend logic is coordinated by the SecurityDashboardEngine class:

- Data ingest & normalization
- PII scanning
- Credential & secret scanning
- Endpoint & modem exposure analysis
- Accounts & access risk analysis
- Schema scanning & risk scoring

A frontend (web or GUI) can call these methods or just read from the
security_findings / table_risk_scores / database_risk_scores tables.
"""

from datetime import datetime
import re
from typing import Dict, List, Optional, Set
import os

import pandas as pd
from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    DateTime,
    Float,
    Text,
    MetaData,
    select,
    inspect,
)
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from sqlalchemy.types import String as SAString, Text as SAText


Base = declarative_base()


class SecurityDashboardEngine:
    """
    Single coordination class for the whole Security Dashboard backend.
    All ORM models and scanner logic live inside this class.
    """

    # ---------------- ORM MODELS (nested) ----------------

    class SecurityFinding(Base):
        """
        Central findings table. Every scanner writes here.
        """
        __tablename__ = "security_findings"

        id = Column(Integer, primary_key=True, autoincrement=True)
        source_db = Column(String(255))         # which DB we scanned
        schema_name = Column(String(255))
        table_name = Column(String(255))
        column_name = Column(String(255))

        finding_type = Column(String(50))       # 'SCHEMA', 'PII', 'SECRET', 'ENDPOINT', 'ACCOUNT'
        severity = Column(String(50))           # 'Low', 'Medium', 'High', 'Critical'
        description = Column(Text)              # text description of the finding
        scanner_name = Column(String(255))

        created_at = Column(DateTime, default=datetime.utcnow)

    class TableRiskScore(Base):
        __tablename__ = "table_risk_scores"

        id = Column(Integer, primary_key=True, autoincrement=True)
        source_db = Column(String(255))
        schema_name = Column(String(255))
        table_name = Column(String(255))
        risk_score = Column(Integer)            # numeric score
        risk_level = Column(String(50))         # Low / Medium / High / Critical
        last_calculated_at = Column(DateTime, default=datetime.utcnow)

    class DatabaseRiskScore(Base):
        __tablename__ = "database_risk_scores"

        id = Column(Integer, primary_key=True, autoincrement=True)
        source_db = Column(String(255), unique=True)
        risk_score = Column(Integer)
        risk_level = Column(String(50))
        last_calculated_at = Column(DateTime, default=datetime.utcnow)

    class DeviceStatus(Base):
        """
        Output table for data ingest & normalization.
        """
        __tablename__ = "device_status"

        id = Column(Integer, primary_key=True, autoincrement=True)
        device_id = Column(String(255), index=True)

        last_seen = Column(DateTime)
        alarm_count = Column(Integer)
        highflow_alarm_count = Column(Integer)

        voltage_vdc = Column(Float)
        last_update = Column(DateTime)

        avg_signal_strength = Column(Float)
        comm_error_count = Column(Integer)

        avg_trend_value = Column(Float)
        risk_score = Column(Float)

    # ---------------- SCORING CONSTANTS ----------------

    POINTS = {
        "SCHEMA_MISSING_PK": 30,
        "SCHEMA_LEGACY_TYPE": 10,
        "SCHEMA_STORED_SQL": 25,
        "PII": 20,
        "SECRET": 40,
        "ENDPOINT": 25,
        "ACCOUNT": 35,
    }

    # ---------------- INIT ----------------

    def __init__(self, results_db_url: str, source_databases: Dict[str, str]):
        """
        results_db_url: DB where findings & scores live (Postgres, SQL Server, etc.)
        source_databases: { 'TelemetryDB': 'driver://user:pass@host/db', ... }
        """
        self.results_db_url = results_db_url
        self.source_databases = source_databases

        self.results_engine = create_engine(self.results_db_url)
        self.SessionLocal = sessionmaker(bind=self.results_engine)

        # Create results tables
        Base.metadata.create_all(bind=self.results_engine)

    # ---------------- Helper: insert finding ----------------

    def _insert_finding(
        self,
        session: Session,
        source_db: str,
        schema_name: Optional[str],
        table_name: Optional[str],
        column_name: Optional[str],
        finding_type: str,
        severity: str,
        description: str,
        scanner_name: str,
    ) -> None:
        finding = self.SecurityFinding(
            source_db=source_db,
            schema_name=schema_name,
            table_name=table_name,
            column_name=column_name,
            finding_type=finding_type,
            severity=severity,
            description=description,
            scanner_name=scanner_name,
        )
        session.add(finding)

    # ---------------- Helper: SQLAlchemy 2.x column sampling ----------------

    def _fetch_column_sample(self, src_engine, table, col, sample_limit: int):
        """
        Helper to run SELECT col LIMIT sample_limit in SQLAlchemy 2.x.
        Returns a list of rows.
        """
        col_obj = getattr(table.c, col.name)
        stmt = select(col_obj).limit(sample_limit)
        with src_engine.connect() as conn:
            return list(conn.execute(stmt))

    # -------------------------------------------------------------------
    # Data Ingest & Normalization 
    # -------------------------------------------------------------------
    def ingest_and_normalize_data(
        self,
        source_db_url: str,
        alarms_query: str = "SELECT * FROM Alarms",
        batteries_query: str = "SELECT * FROM Batteries",
        messages_query: str = "SELECT * FROM Messages",
        trends_query: str = "SELECT * FROM Trends",
    ) -> pd.DataFrame:

        src_engine = create_engine(source_db_url)

        def load(query: str) -> pd.DataFrame:
            return pd.read_sql_query(query, src_engine)

        # 1) Load data from SQL
        alarms = load(alarms_query)
        batteries = load(batteries_query)
        messages = load(messages_query)
        trends = load(trends_query)

        # 2) Normalize device_id
        for df in [alarms, batteries, messages, trends]:
            df["device_id"] = df["device_id"].astype(str).str.upper()

        # 3) Timestamps
        alarms["timestamp_start"] = pd.to_datetime(alarms["timestamp_start"])
        alarms["timestamp_end"] = pd.to_datetime(alarms["timestamp_end"])
        batteries["last_update"] = pd.to_datetime(batteries["last_update"])
        messages["msg_timestamp"] = pd.to_datetime(messages["msg_timestamp"])
        trends["trend_timestamp"] = pd.to_datetime(trends["trend_timestamp"])

        # 4) Alarm category
        alarms["alarm_category"] = alarms["alarm_type"].apply(
            lambda x: "HighFlow" if "Hi Alarm" in str(x) else "Other"
        )

        # 5) Battery cleanup
        batteries.loc[batteries["voltage_vdc"] == 0.0, "voltage_vdc"] = pd.NA

        # 6) Signal strength + comms errors
        messages["signal_strength"] = (
            messages["message_text"]
            .astype(str)
            .str.extract(r"(\d+)")
            .astype(float)
        )

        messages["comm_error_flag"] = messages["message_text"].str.contains(
            "Call setup failed", case=False, na=False
        )

        # 7) Trend cleanup
        trends.loc[trends["value"] < 0, "value"] = pd.NA

        # 8) Aggregations
        alarm_agg = (
            alarms.groupby("device_id")
            .agg(
                alarm_count=("alarm_type", "count"),
                highflow_alarm_count=("alarm_category", lambda s: (s == "HighFlow").sum()),
                last_alarm=("timestamp_start", "max"),
            )
            .reset_index()
        )

        battery_agg = (
            batteries.sort_values("last_update")
            .groupby("device_id")
            .tail(1)[["device_id", "voltage_vdc", "last_update"]]
        )

        msg_agg = (
            messages.groupby("device_id")
            .agg(
                avg_signal_strength=("signal_strength", "mean"),
                comm_error_count=("comm_error_flag", "sum"),
                last_msg=("msg_timestamp", "max"),
            )
            .reset_index()
        )

        trend_agg = (
            trends.groupby("device_id")
            .agg(avg_trend_value=("value", "mean"))
            .reset_index()
        )

        # 9) Merge into DeviceStatus-style frame
        device_status = (
            alarm_agg
            .merge(battery_agg, on="device_id", how="outer")
            .merge(msg_agg, on="device_id", how="outer")
            .merge(trend_agg, on="device_id", how="outer")
        )

        # 10) Last seen timestamp
        device_status["last_seen"] = device_status[
            ["last_alarm", "last_update", "last_msg"]
        ].max(axis=1)

        # 11) Risk score
        device_status["risk_score"] = (
            device_status["alarm_count"].fillna(0) * 1.5 +
            device_status["comm_error_count"].fillna(0) * 2.0 +
            (9.0 - device_status["voltage_vdc"].fillna(9.0)) +
            (25 - device_status["avg_signal_strength"].fillna(25)) * 0.2
        )

        # 12) Write to results DB
        device_status.to_sql(
            self.DeviceStatus.__tablename__,
            self.results_engine,
            if_exists="replace",
            index=False,
        )

        print(f"[DataIngest] Data ingest complete — {len(device_status)} devices.")
        return device_status




    # -------------------------------------------------------------------
    # PII Scanner
    # -------------------------------------------------------------------
    EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}")
    PHONE_RE = re.compile(r"\+?\d[\d\s().-]{7,}\d")
    NAME_RE = re.compile(r"\b[A-Z][a-z]+ [A-Z][a-z]+\b")
    ADDRESS_RE = re.compile(r"\d{1,6}\s+\w+(?:\s+\w+)*\s+(St|Street|Ave|Road|Rd|Blvd|Lane|Ln)\b", re.I)

    def _detect_pii_types(self, value: str) -> Set[str]:
        hits: Set[str] = set()
        if not value:
            return hits
        if self.EMAIL_RE.search(value):
            hits.add("email")
        if self.PHONE_RE.search(value):
            hits.add("phone")
        if self.NAME_RE.search(value):
            hits.add("name")
        if self.ADDRESS_RE.search(value):
            hits.add("address")
        return hits

    def run_pii_scanner_for_engine(
        self,
        source_db_name: str,
        engine,
        session: Session,
        sample_limit: int = 1000,
        min_matches: int = 5,
    ) -> None:
        """
        Scan all string columns in a DB for simple PII patterns.
        """
        meta = MetaData()
        meta.reflect(bind=engine)

        for table_name, table in meta.tables.items():
            schema_name = table.schema
            for col in table.columns:
                if not isinstance(col.type, (SAString, SAText)):
                    continue

                results = self._fetch_column_sample(engine, table, col, sample_limit)

                counts: Dict[str, int] = {}
                example: Dict[str, Optional[str]] = {}
                sample_size = 0

                for (val,) in results:
                    sample_size += 1
                    s = str(val) if val is not None else ""
                    hits = self._detect_pii_types(s)
                    for t in hits:
                        counts[t] = counts.get(t, 0) + 1
                        if t not in example:
                            example[t] = s

                for t, c in counts.items():
                    if c >= min_matches and sample_size > 0:
                        severity = "High" if t in ("name", "address") else "Medium"
                        desc = f"{t} detected in {c}/{sample_size} sampled rows"
                        self._insert_finding(
                            session,
                            source_db=source_db_name,
                            schema_name=schema_name,
                            table_name=table_name,
                            column_name=col.name,
                            finding_type="PII",
                            severity=severity,
                            description=desc,
                            scanner_name="PII Scanner",
                        )

        print(f"[PIIScanner] PII scan complete for {source_db_name}.")

    # -------------------------------------------------------------------
    # Credential & Secret Scanner
    # -------------------------------------------------------------------
    SECRET_PATTERNS = {
        "password": re.compile(r"password\s*[:=]\s*['\"]?.+['\"]?", re.I),
        "token": re.compile(r"token\s*[:=]\s*['\"]?.+['\"]?", re.I),
        "api_key": re.compile(r"api[_-]?key\s*[:=]\s*['\"]?.+['\"]?", re.I),
    }

    def run_secret_scanner_for_engine(
        self,
        source_db_name: str,
        engine,
        session: Session,
        sample_limit: int = 1000,
    ) -> None:
        """
        VERY simple secret scanner: looks for 'password', 'token', 'api_key' in text columns.
        """
        meta = MetaData()
        meta.reflect(bind=engine)

        for table_name, table in meta.tables.items():
            schema_name = table.schema
            for col in table.columns:
                if not isinstance(col.type, (SAString, SAText)):
                    continue

                results = self._fetch_column_sample(engine, table, col, sample_limit)

                hits = 0
                for (val,) in results:
                    s = str(val) if val is not None else ""
                    if any(p.search(s) for p in self.SECRET_PATTERNS.values()):
                        hits += 1

                if hits > 0:
                    desc = f"Possible secrets detected in column (approx {hits} hits in sample)"
                    self._insert_finding(
                        session,
                        source_db=source_db_name,
                        schema_name=schema_name,
                        table_name=table_name,
                        column_name=col.name,
                        finding_type="SECRET",
                        severity="High",
                        description=desc,
                        scanner_name="Secret Scanner",
                    )

        print(f"[SecretScanner] Secret scan complete for {source_db_name}.")

    # -------------------------------------------------------------------
    # Endpoint & Modem Exposure Analyzer
    # -------------------------------------------------------------------
    IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    HOST_RE = re.compile(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
    MODEM_ID_RE = re.compile(r"\b\d{15,20}\b")

    def run_endpoint_scanner_for_engine(
        self,
        source_db_name: str,
        src_engine,
        session: Session,
        sample_limit: int = 1000,
    ) -> None:
        meta = MetaData()
        meta.reflect(bind=src_engine)

        for table_name, table in meta.tables.items():
            schema_name = table.schema
            for col in table.columns:
                if not isinstance(col.type, (SAString, SAText)):
                    continue

                results = self._fetch_column_sample(src_engine, table, col, sample_limit)

                ip_hits = host_hits = modem_hits = 0
                for (val,) in results:
                    s = str(val) if val is not None else ""
                    if self.IP_RE.search(s):
                        ip_hits += 1
                    if self.HOST_RE.search(s):
                        host_hits += 1
                    if self.MODEM_ID_RE.search(s):
                        modem_hits += 1

                if ip_hits or host_hits or modem_hits:
                    desc = f"IPs:{ip_hits}, hostnames:{host_hits}, modem IDs:{modem_hits} found in samples"
                    self._insert_finding(
                        session,
                        source_db=source_db_name,
                        schema_name=schema_name,
                        table_name=table_name,
                        column_name=col.name,
                        finding_type="ENDPOINT",
                        severity="High",
                        description=desc,
                        scanner_name="Endpoint Scanner",
                    )

        print(f"[EndpointScanner] Endpoint scan complete for {source_db_name}.")

    # -------------------------------------------------------------------
    # Accounts & Access Risk Analyzer
    # -------------------------------------------------------------------
    ADMIN_USERNAMES = {"sa", "admin", "administrator", "root"}

    def run_account_scanner_for_engine(
        self,
        source_db_name: str,
        src_engine,
        session: Session,
        sample_limit: int = 1000,
    ) -> None:
        meta = MetaData()
        meta.reflect(bind=src_engine)

        for table_name, table in meta.tables.items():
            schema_name = table.schema

            # guess "user" tables
            if not any(k in table_name.lower() for k in ("user", "account", "login", "member")):
                continue

            # find username columns
            user_cols = [c for c in table.columns if "user" in c.name.lower() or "login" in c.name.lower()]
            if not user_cols:
                continue

            for col in user_cols:
                results = self._fetch_column_sample(src_engine, table, col, sample_limit)

                admin_hits = 0
                for (val,) in results:
                    s = str(val).lower() if val is not None else ""
                    if s in self.ADMIN_USERNAMES:
                        admin_hits += 1

                if admin_hits > 0:
                    desc = f"Shared/privileged usernames detected in {admin_hits} sampled rows"
                    self._insert_finding(
                        session,
                        source_db=source_db_name,
                        schema_name=schema_name,
                        table_name=table_name,
                        column_name=col.name,
                        finding_type="ACCOUNT",
                        severity="High",
                        description=desc,
                        scanner_name="Account Scanner",
                    )

        print(f"[AccountScanner] Account scan complete for {source_db_name}.")

    # -------------------------------------------------------------------
    # Schema & Risk Scoring Engine
    # -------------------------------------------------------------------
    def run_schema_scanner_for_engine(
        self,
        source_db_name: str,
        src_engine,
        session: Session,
    ) -> None:
        inspector = inspect(src_engine)
        print(f"[SchemaScanner] Schema scan for {source_db_name} ...")

        for table_name in inspector.get_table_names():
            schema_name = None  # fill if your DB supports schemas here

            # missing PK
            pk_info = inspector.get_pk_constraint(table_name)
            pk_cols = pk_info.get("constrained_columns", []) if pk_info else []
            if not pk_cols:
                self._insert_finding(
                    session,
                    source_db=source_db_name,
                    schema_name=schema_name,
                    table_name=table_name,
                    column_name=None,
                    finding_type="SCHEMA",
                    severity="High",
                    description="Table has no primary key defined",
                    scanner_name="Schema Scanner",
                )

            # legacy / risky types + columns that look like stored SQL
            for col in inspector.get_columns(table_name):
                col_name = col["name"]
                col_type = str(col["type"]).lower()

                if any(t in col_type for t in ("text", "ntext", "image")):
                    self._insert_finding(
                        session,
                        source_db=source_db_name,
                        schema_name=schema_name,
                        table_name=table_name,
                        column_name=col_name,
                        finding_type="SCHEMA",
                        severity="Medium",
                        description=f"Legacy data type: {col_type}",
                        scanner_name="Schema Scanner",
                    )

                if "varchar" in col_type and "max" in col_type:
                    self._insert_finding(
                        session,
                        source_db=source_db_name,
                        schema_name=schema_name,
                        table_name=table_name,
                        column_name=col_name,
                        finding_type="SCHEMA",
                        severity="Medium",
                        description=f"Unbounded text type: {col_type}",
                        scanner_name="Schema Scanner",
                    )

                if any(key in col_name.lower() for key in ("sql", "query", "command", "script")):
                    self._insert_finding(
                        session,
                        source_db=source_db_name,
                        schema_name=schema_name,
                        table_name=table_name,
                        column_name=col_name,
                        finding_type="SCHEMA",
                        severity="High",
                        description="Column name suggests stored SQL/command text",
                        scanner_name="Schema Scanner",
                    )

        print(f"[SchemaScanner] Schema scan complete for {source_db_name}.")

    # -------------------- scoring helpers --------------------
    @staticmethod
    def _risk_level_from_score(score: int) -> str:
        if score < 20:
            return "Low"
        if score < 50:
            return "Medium"
        if score < 100:
            return "High"
        return "Critical"

    def calculate_table_scores(self) -> None:
        """
        Combine *all* findings into per-table risk scores.
        """
        session = self.SessionLocal()
        session.query(self.TableRiskScore).delete()

        findings = session.query(self.SecurityFinding).all()
        score_map: Dict[tuple, int] = {}

        for f in findings:
            key = (f.source_db, f.schema_name or "dbo", f.table_name or "<N/A>")
            score_map.setdefault(key, 0)

            if f.finding_type == "SCHEMA":
                desc = (f.description or "").lower()
                if "no primary key" in desc:
                    score_map[key] += self.POINTS["SCHEMA_MISSING_PK"]
                elif "legacy data type" in desc:
                    score_map[key] += self.POINTS["SCHEMA_LEGACY_TYPE"]
                elif "unbounded text type" in desc or "stored sql" in desc:
                    score_map[key] += self.POINTS["SCHEMA_STORED_SQL"]
                else:
                    score_map[key] += 5
            elif f.finding_type in ("PII", "SECRET", "ENDPOINT", "ACCOUNT"):
                score_map[key] += self.POINTS.get(f.finding_type, 5)
            else:
                score_map[key] += 5

        for (source_db, schema_name, table_name), score in score_map.items():
            session.add(
                self.TableRiskScore(
                    source_db=source_db,
                    schema_name=schema_name,
                    table_name=table_name,
                    risk_score=score,
                    risk_level=self._risk_level_from_score(score),
                    last_calculated_at=datetime.utcnow(),
                )
            )

        session.commit()
        session.close()
        print("[RiskEngine] Table risk scores calculated.")

    def calculate_database_scores(self) -> None:
        """
        Aggregate table scores into per-database scores.
        """
        session = self.SessionLocal()
        session.query(self.DatabaseRiskScore).delete()

        rows = session.query(self.TableRiskScore).all()
        agg: Dict[str, int] = {}
        for r in rows:
            agg[r.source_db] = agg.get(r.source_db, 0) + r.risk_score

        for source_db, total in agg.items():
            session.add(
                self.DatabaseRiskScore(
                    source_db=source_db,
                    risk_score=total,
                    risk_level=self._risk_level_from_score(total),
                    last_calculated_at=datetime.utcnow(),
                )
            )

        session.commit()
        session.close()
        print("[RiskEngine] Database risk scores calculated.")

    # -------------------------------------------------------------------
    # Orchestration helpers
    # -------------------------------------------------------------------
    def run_all_scanners_for_source(self, source_db_name: str, source_db_url: str) -> None:
        """
        Run ALL scanners (schema, PII, secret, endpoint, account) for one DB.
        """
        src_engine = create_engine(source_db_url)
        session = self.SessionLocal()

        self.run_schema_scanner_for_engine(source_db_name, src_engine, session)
        self.run_pii_scanner_for_engine(source_db_name, src_engine, session)
        self.run_secret_scanner_for_engine(source_db_name, src_engine, session)
        self.run_endpoint_scanner_for_engine(source_db_name, src_engine, session)
        self.run_account_scanner_for_engine(source_db_name, src_engine, session)

        session.commit()
        session.close()

    def run_all_sources(self) -> None:
        """
        Run all scanners for every DB in self.source_databases,
        then compute table & database scores.
        """
        for name, url in self.source_databases.items():
            print(f"\n=== Scanning source DB: {name} ===")
            try:
                self.run_all_scanners_for_source(name, url)
            except Exception as e:
                print(f"[ERROR] Failed scanning {name}: {e}")

        self.calculate_table_scores()
        self.calculate_database_scores()


# -------------------------------------------------------------------
# Example usage – Multi-database scan for your SQL Server
# -------------------------------------------------------------------
if __name__ == "__main__":

    # Results DB: SQLite file in the same folder as the root folder
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))        # Functions/Backend
    ROOT_DIR = os.path.dirname(os.path.dirname(BASE_DIR))        # DynamicUtilityApp root
    DB_PATH = os.path.join(ROOT_DIR, "security_dashboard_results.db")

    RESULTS_DB_URL = f"sqlite:///{DB_PATH.replace(os.sep, '/')}"

    # Source DBs are still your SQL Server databases
    SERVER = r"localhost\SQLEXPRESS"
    DRIVER = "ODBC+Driver+17+for+SQL+Server"

    # All source DBs you want to scan
    SOURCE_DATABASES = {
        "MCRWS-Telog": (
            f"mssql+pyodbc://@{SERVER}/MCRWS-Telog"
            f"?driver={DRIVER}"
            "&trusted_connection=yes"
        ),
        "OPSDC": (
            f"mssql+pyodbc://@{SERVER}/OPSDC"
            f"?driver={DRIVER}"
            "&trusted_connection=yes"
        ),
        "OPSMOUNT": (
            f"mssql+pyodbc://@{SERVER}/OPSMOUNT"
            f"?driver={DRIVER}"
            "&trusted_connection=yes"
        ),
        "OPSREDOA": (
            f"mssql+pyodbc://@{SERVER}/OPSREDOA"
            f"?driver={DRIVER}"
            "&trusted_connection=yes"
        ),
        "OPSTENMI": (
            f"mssql+pyodbc://@{SERVER}/OPSTENMI"
            f"?driver={DRIVER}"
            "&trusted_connection=yes"
        ),
        "OPSTSBP": (
            f"mssql+pyodbc://@{SERVER}/OPSTSBP"
            f"?driver={DRIVER}"
            "&trusted_connection=yes"
        ),
    }

    dashboard = SecurityDashboardEngine(RESULTS_DB_URL, SOURCE_DATABASES)
    dashboard.run_all_sources()
