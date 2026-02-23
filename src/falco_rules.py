#!/usr/bin/env python3
"""
Falco-inspired runtime security rule engine.
Evaluates security events against defined rules and maintains audit logs.
"""

import json
import sqlite3
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from pathlib import Path
import yaml


@dataclass
class Rule:
    """Represents a security rule."""
    id: str
    name: str
    description: str
    condition: Dict[str, Any]  # {field: str, operator: "eq"|"ne"|"contains"|"regex"|"gt"|"lt", value: any}
    output_format: str
    priority: str = "warning"  # debug/info/notice/warning/error/critical
    tags: List[str] = field(default_factory=list)
    enabled: bool = True


@dataclass
class SecurityEvent:
    """Represents a security event."""
    id: str
    rule_id: str
    source: str
    pid: int = 0
    user: str = ""
    command: str = ""
    file_path: str = ""
    network: str = ""
    severity: str = "notice"
    timestamp: str = ""


class FalcoEngine:
    """Runtime security rule evaluation engine."""

    def __init__(self, db_path: str = "~/.blackroad/falco.db"):
        """Initialize FalcoEngine with SQLite backend."""
        self.db_path = Path(db_path).expanduser()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        self._init_preset_rules()

    def _init_db(self):
        """Initialize SQLite database schema."""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS rules (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                description TEXT,
                condition TEXT,
                output_format TEXT,
                priority TEXT,
                tags TEXT,
                enabled INTEGER
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                id TEXT PRIMARY KEY,
                rule_id TEXT NOT NULL,
                source TEXT NOT NULL,
                pid INTEGER,
                user TEXT,
                command TEXT,
                file_path TEXT,
                network TEXT,
                severity TEXT,
                timestamp TEXT
            )
        """)
        
        conn.commit()
        conn.close()

    def _init_preset_rules(self):
        """Load 8 built-in security rules."""
        preset_rules = [
            {
                "name": "shell_in_container",
                "description": "Detect shell spawned in container",
                "condition": {
                    "field": "source",
                    "operator": "contains",
                    "value": "container"
                },
                "output_format": "Shell spawned in container: %{user} %{command}",
                "priority": "critical",
                "tags": ["container", "shell"]
            },
            {
                "name": "sensitive_file_read",
                "description": "Detect read access to sensitive files",
                "condition": {
                    "field": "file_path",
                    "operator": "regex",
                    "value": r"^(/etc/shadow|/etc/passwd|/root/\.ssh)"
                },
                "output_format": "Sensitive file accessed: %{file_path} by %{user}",
                "priority": "error",
                "tags": ["file", "sensitive"]
            },
            {
                "name": "outbound_connection_to_c2",
                "description": "Detect suspicious outbound connections",
                "condition": {
                    "field": "network",
                    "operator": "contains",
                    "value": "c2"
                },
                "output_format": "Suspicious connection: %{network} from %{user}",
                "priority": "critical",
                "tags": ["network", "c2", "threat"]
            },
            {
                "name": "privilege_escalation",
                "description": "Detect privilege escalation attempts",
                "condition": {
                    "field": "command",
                    "operator": "regex",
                    "value": r"(sudo|su|sudo -i)"
                },
                "output_format": "Privilege escalation attempt: %{command} by %{user}",
                "priority": "error",
                "tags": ["privilege", "escalation"]
            },
            {
                "name": "crypto_mining_process",
                "description": "Detect cryptocurrency mining processes",
                "condition": {
                    "field": "command",
                    "operator": "regex",
                    "value": r"(xmrig|monero|stratum|hashrate)"
                },
                "output_format": "Crypto mining detected: %{command}",
                "priority": "error",
                "tags": ["mining", "malware"]
            },
            {
                "name": "ssh_brute_force",
                "description": "Detect SSH brute force attempts",
                "condition": {
                    "field": "source",
                    "operator": "contains",
                    "value": "ssh"
                },
                "output_format": "SSH activity detected: %{source}",
                "priority": "warning",
                "tags": ["ssh", "authentication"]
            },
            {
                "name": "large_file_write",
                "description": "Detect large file writes (potential data exfiltration)",
                "condition": {
                    "field": "file_path",
                    "operator": "contains",
                    "value": "exfil"
                },
                "output_format": "Large file write detected: %{file_path} by %{user}",
                "priority": "warning",
                "tags": ["file", "exfiltration"]
            },
            {
                "name": "suspicious_cron",
                "description": "Detect suspicious cron job modifications",
                "condition": {
                    "field": "file_path",
                    "operator": "regex",
                    "value": r"/var/spool/cron"
                },
                "output_format": "Cron modification detected: %{file_path} by %{user}",
                "priority": "warning",
                "tags": ["cron", "persistence"]
            }
        ]
        
        for i, rule_data in enumerate(preset_rules):
            try:
                self.add_rule(
                    name=rule_data["name"],
                    description=rule_data["description"],
                    condition=rule_data["condition"],
                    output_format=rule_data["output_format"],
                    priority=rule_data.get("priority", "warning"),
                    tags=rule_data.get("tags", [])
                )
            except sqlite3.IntegrityError:
                pass  # Rule already exists

    def add_rule(
        self,
        name: str,
        description: str,
        condition: Dict[str, Any],
        output_format: str,
        priority: str = "warning",
        tags: List[str] = None
    ) -> Rule:
        """Add a security rule."""
        if tags is None:
            tags = []
        
        rule_id = name.lower().replace(" ", "_")
        rule = Rule(
            id=rule_id,
            name=name,
            description=description,
            condition=condition,
            output_format=output_format,
            priority=priority,
            tags=tags,
            enabled=True
        )
        
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO rules
            (id, name, description, condition, output_format, priority, tags, enabled)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            rule.id, rule.name, rule.description, json.dumps(rule.condition),
            rule.output_format, rule.priority, json.dumps(rule.tags), 1
        ))
        conn.commit()
        conn.close()
        
        return rule

    def evaluate(self, event_data: Dict[str, Any]) -> List[str]:
        """Check event against all enabled rules, returns matching rule names."""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM rules WHERE enabled = 1")
        rows = cursor.fetchall()
        conn.close()
        
        matching_rules = []
        
        for row in rows:
            rule = self._row_to_rule(row)
            if self._evaluate_condition(rule.condition, event_data):
                matching_rules.append(rule.name)
                
                # Record the security event
                event_id = f"{rule.id}_{int(datetime.now().timestamp())}"
                self._record_event(
                    event_id=event_id,
                    rule_id=rule.id,
                    source=event_data.get("source", "unknown"),
                    pid=event_data.get("pid", 0),
                    user=event_data.get("user", ""),
                    command=event_data.get("command", ""),
                    file_path=event_data.get("file_path", ""),
                    network=event_data.get("network", ""),
                    severity=rule.priority
                )
        
        return matching_rules

    def _evaluate_condition(self, condition: Dict[str, Any], event_data: Dict[str, Any]) -> bool:
        """Evaluate if event matches condition."""
        field = condition.get("field")
        operator = condition.get("operator")
        value = condition.get("value")
        
        event_value = event_data.get(field, "")
        
        if operator == "eq":
            return event_value == value
        elif operator == "ne":
            return event_value != value
        elif operator == "contains":
            return str(value).lower() in str(event_value).lower()
        elif operator == "regex":
            try:
                return re.search(value, str(event_value)) is not None
            except re.error:
                return False
        elif operator == "gt":
            try:
                return float(event_value) > float(value)
            except (ValueError, TypeError):
                return False
        elif operator == "lt":
            try:
                return float(event_value) < float(value)
            except (ValueError, TypeError):
                return False
        
        return False

    def load_rules_file(self, path: str):
        """Load YAML rule definitions from file."""
        with open(path, 'r') as f:
            data = yaml.safe_load(f)
        
        if data and 'rules' in data:
            for rule_data in data['rules']:
                self.add_rule(
                    name=rule_data['name'],
                    description=rule_data.get('description', ''),
                    condition=rule_data.get('condition', {}),
                    output_format=rule_data.get('output_format', ''),
                    priority=rule_data.get('priority', 'warning'),
                    tags=rule_data.get('tags', [])
                )

    def enable_rule(self, name: str):
        """Enable a rule by name."""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        cursor.execute("UPDATE rules SET enabled = 1 WHERE name = ?", (name,))
        conn.commit()
        conn.close()

    def disable_rule(self, name: str):
        """Disable a rule by name."""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        cursor.execute("UPDATE rules SET enabled = 0 WHERE name = ?", (name,))
        conn.commit()
        conn.close()

    def get_events(
        self,
        severity: Optional[str] = None,
        rule: Optional[str] = None,
        n: int = 50
    ) -> List[SecurityEvent]:
        """Query security events with optional filtering."""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        query = "SELECT * FROM security_events"
        params = []
        
        if severity:
            query += " WHERE severity = ?"
            params.append(severity)
        
        if rule:
            if severity:
                query += " AND rule_id = ?"
            else:
                query += " WHERE rule_id = ?"
            params.append(rule)
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(n)
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        return [self._row_to_event(row) for row in rows]

    def stats(self) -> Dict[str, Any]:
        """Generate security statistics."""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        # Events in last minute
        one_minute_ago = (datetime.now() - timedelta(minutes=1)).isoformat()
        cursor.execute(
            "SELECT COUNT(*) FROM security_events WHERE timestamp > ?",
            (one_minute_ago,)
        )
        events_per_minute = cursor.fetchone()[0]
        
        # Top rules triggered
        cursor.execute("""
            SELECT rule_id, COUNT(*) as count FROM security_events
            GROUP BY rule_id ORDER BY count DESC LIMIT 5
        """)
        top_rules = [(row[0], row[1]) for row in cursor.fetchall()]
        
        # Top users involved in events
        cursor.execute("""
            SELECT user, COUNT(*) as count FROM security_events
            WHERE user != ''
            GROUP BY user ORDER BY count DESC LIMIT 5
        """)
        top_users = [(row[0], row[1]) for row in cursor.fetchall()]
        
        conn.close()
        
        return {
            "events_per_minute": events_per_minute,
            "top_rules": top_rules,
            "top_users": top_users
        }

    def export_rules(self, output_path: str):
        """Export rules to Falco-compatible YAML."""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM rules")
        rows = cursor.fetchall()
        conn.close()
        
        rules_list = []
        for row in rows:
            rule = self._row_to_rule(row)
            rules_list.append({
                "id": rule.id,
                "name": rule.name,
                "description": rule.description,
                "condition": rule.condition,
                "output_format": rule.output_format,
                "priority": rule.priority,
                "tags": rule.tags
            })
        
        output_data = {"rules": rules_list}
        
        with open(output_path, 'w') as f:
            yaml.dump(output_data, f, default_flow_style=False)

    def _record_event(
        self,
        event_id: str,
        rule_id: str,
        source: str,
        pid: int,
        user: str,
        command: str,
        file_path: str,
        network: str,
        severity: str
    ):
        """Record a security event in the database."""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO security_events
            (id, rule_id, source, pid, user, command, file_path, network, severity, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event_id, rule_id, source, pid, user, command, file_path, network, severity,
            datetime.now().isoformat()
        ))
        conn.commit()
        conn.close()

    def _row_to_rule(self, row: tuple) -> Rule:
        """Convert database row to Rule object."""
        return Rule(
            id=row[0],
            name=row[1],
            description=row[2],
            condition=json.loads(row[3]) if row[3] else {},
            output_format=row[4],
            priority=row[5],
            tags=json.loads(row[6]) if row[6] else [],
            enabled=bool(row[7])
        )

    def _row_to_event(self, row: tuple) -> SecurityEvent:
        """Convert database row to SecurityEvent object."""
        return SecurityEvent(
            id=row[0],
            rule_id=row[1],
            source=row[2],
            pid=row[3],
            user=row[4],
            command=row[5],
            file_path=row[6],
            network=row[7],
            severity=row[8],
            timestamp=row[9]
        )


def main():
    """CLI entry point."""
    import sys
    
    engine = FalcoEngine()
    
    if len(sys.argv) < 2:
        print("Usage: python falco_rules.py [command] [args...]")
        print("Commands:")
        print("  rules                      - List all rules")
        print("  events [--severity SEV]    - Get security events")
        print("  stats                      - Show statistics")
        print("  add-rule <name> <desc> <condition> - Add rule")
        print("  enable <rule_name>         - Enable rule")
        print("  disable <rule_name>        - Disable rule")
        print("  export <output_file>       - Export rules to YAML")
        print("  evaluate <event_json>      - Evaluate event")
        return
    
    command = sys.argv[1]
    
    if command == "rules":
        conn = sqlite3.connect(str(engine.db_path))
        cursor = conn.cursor()
        cursor.execute("SELECT name, description, priority, enabled FROM rules")
        for row in cursor.fetchall():
            status = "enabled" if row[3] else "disabled"
            print(f"{row[0]} ({row[2]}) [{status}] - {row[1]}")
        conn.close()
    
    elif command == "events":
        severity = None
        if "--severity" in sys.argv:
            idx = sys.argv.index("--severity")
            severity = sys.argv[idx + 1]
        
        events = engine.get_events(severity=severity)
        for event in events:
            print(f"{event.timestamp} - {event.rule_id} ({event.severity}): {event.source}")
    
    elif command == "stats":
        stats = engine.stats()
        print(f"Events/min: {stats['events_per_minute']}")
        print("Top rules:", stats['top_rules'])
        print("Top users:", stats['top_users'])
    
    elif command == "add-rule":
        name, desc = sys.argv[2], sys.argv[3]
        condition_json = sys.argv[4] if len(sys.argv) > 4 else "{}"
        condition = json.loads(condition_json)
        rule = engine.add_rule(name, desc, condition, f"Rule {name} triggered")
        print(f"Added rule: {rule.name}")
    
    elif command == "enable":
        name = sys.argv[2]
        engine.enable_rule(name)
        print(f"Enabled {name}")
    
    elif command == "disable":
        name = sys.argv[2]
        engine.disable_rule(name)
        print(f"Disabled {name}")
    
    elif command == "export":
        output = sys.argv[2] if len(sys.argv) > 2 else "rules.yaml"
        engine.export_rules(output)
        print(f"Exported rules to {output}")
    
    elif command == "evaluate":
        event_json = sys.argv[2] if len(sys.argv) > 2 else "{}"
        event_data = json.loads(event_json)
        matches = engine.evaluate(event_data)
        if matches:
            print(f"Triggered rules: {', '.join(matches)}")
        else:
            print("No rules triggered")


if __name__ == "__main__":
    main()
