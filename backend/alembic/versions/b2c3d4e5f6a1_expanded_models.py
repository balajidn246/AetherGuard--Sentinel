"""Expanded models: ueba_snapshots, audit_logs, cases, detection_rules

Revision ID: b2c3d4e5f6a1
Revises: 77d667da55a8
Create Date: 2026-09-04 12:40:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b2c3d4e5f6a1'
down_revision: Union[str, None] = '77d667da55a8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. ueba_snapshots
    op.create_table(
        'ueba_snapshots',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('tenant_id', sa.String(length=36), nullable=False),
        sa.Column('username', sa.String(length=100), nullable=False),
        sa.Column('hour_bucket', sa.String(length=20), nullable=False),
        sa.Column('event_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('avg_risk_score', sa.Float(), nullable=False, server_default='20.0'),
        sa.Column('peak_risk_score', sa.Float(), nullable=False, server_default='20.0'),
        sa.Column('anomaly_flag', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_ueba_snapshots_tenant_id'), 'ueba_snapshots', ['tenant_id'], unique=False)
    op.create_index(op.f('ix_ueba_snapshots_username'), 'ueba_snapshots', ['username'], unique=False)
    op.create_index(op.f('ix_ueba_snapshots_hour_bucket'), 'ueba_snapshots', ['hour_bucket'], unique=False)

    # 2. audit_logs
    op.create_table(
        'audit_logs',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('tenant_id', sa.String(length=36), nullable=False),
        sa.Column('actor_id', sa.String(length=100), nullable=False),
        sa.Column('actor_username', sa.String(length=100), nullable=False),
        sa.Column('action', sa.String(length=100), nullable=False),
        sa.Column('resource', sa.String(length=100), nullable=False),
        sa.Column('resource_id', sa.String(length=100), nullable=True),
        sa.Column('details', sa.JSON(), nullable=True),
        sa.Column('result', sa.String(length=20), nullable=True, server_default='success'),
        sa.Column('ip_address', sa.String(length=45), nullable=True, server_default=''),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_audit_logs_tenant_id'), 'audit_logs', ['tenant_id'], unique=False)

    # 3. cases
    op.create_table(
        'cases',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('tenant_id', sa.String(length=36), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.String(length=2000), nullable=True),
        sa.Column('status', sa.String(length=30), nullable=False, server_default='open'),
        sa.Column('priority', sa.String(length=20), nullable=False, server_default='medium'),
        sa.Column('owner_id', sa.String(length=100), nullable=True),
        sa.Column('signal_ids', sa.JSON(), nullable=True),
        sa.Column('incident_ids', sa.JSON(), nullable=True),
        sa.Column('evidence_refs', sa.JSON(), nullable=True),
        sa.Column('timeline', sa.JSON(), nullable=True),
        sa.Column('notes', sa.JSON(), nullable=True),
        sa.Column('ai_summary', sa.String(length=5000), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_cases_tenant_id'), 'cases', ['tenant_id'], unique=False)

    # 4. detection_rules
    op.create_table(
        'detection_rules',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('tenant_id', sa.String(length=36), nullable=False),
        sa.Column('rule_id', sa.String(length=100), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.String(length=2000), nullable=True),
        sa.Column('severity', sa.String(length=20), nullable=False, server_default='medium'),
        sa.Column('rule_type', sa.String(length=20), nullable=False, server_default='yaml'),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('content', sa.JSON(), nullable=True),
        sa.Column('mitre_techniques', sa.JSON(), nullable=True),
        sa.Column('version', sa.String(length=20), nullable=False, server_default='1.0.0'),
        sa.Column('author', sa.String(length=100), nullable=False, server_default='AetherGuard'),
        sa.Column('false_positive_notes', sa.String(length=1000), nullable=True),
        sa.Column('hit_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_detection_rules_tenant_id'), 'detection_rules', ['tenant_id'], unique=False)
    op.create_index(op.f('ix_detection_rules_rule_id'), 'detection_rules', ['rule_id'], unique=True)


def downgrade() -> None:
    op.drop_table('detection_rules')
    op.drop_table('cases')
    op.drop_table('audit_logs')
    op.drop_table('ueba_snapshots')
