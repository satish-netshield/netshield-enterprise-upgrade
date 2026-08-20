"""Import JSON Lines security events into the NetShield database."""

import json
from pathlib import Path
from typing import Any
from uuid import uuid4

from src.collectors.event_normalizer import normalise_event
from src.utils.database import (
    complete_import_batch,
    save_rejected_event,
    save_security_event,
    start_import_batch,
)


def identify_source_type(source_file: Path) -> str:
    """Identify the expected source type from the filename."""
    return source_file.stem.split("_", maxsplit=1)[0].lower()


def reject_record(
    database_path: Path,
    source_file: Path,
    batch_id: str,
    line_number: int,
    reason: str,
    raw_line: str,
) -> None:
    """Preserve a rejected line and its reason."""
    save_rejected_event(
        database_path=database_path,
        source_file=source_file.name,
        batch_id=batch_id,
        line_number=line_number,
        reason=reason,
        raw_event=raw_line.rstrip("\n"),
    )


def import_jsonl_file(
    database_path: Path,
    source_file: Path,
) -> dict[str, Any]:
    """Import one JSONL file and return its processing summary."""
    if source_file.suffix.lower() != ".jsonl":
        raise ValueError(
            f"Unsupported file extension: {source_file.suffix}"
        )

    if not source_file.is_file():
        raise FileNotFoundError(
            f"Source file not found: {source_file}"
        )

    batch_id = str(uuid4())
    source_type = identify_source_type(source_file)

    total_records = 0
    accepted_records = 0
    rejected_records = 0

    start_import_batch(
        database_path=database_path,
        batch_id=batch_id,
        source_file=source_file.name,
        source_type=source_type,
    )

    try:
        with source_file.open(
            "r",
            encoding="utf-8",
        ) as event_file:
            for line_number, raw_line in enumerate(event_file, 1):
                total_records += 1
                stripped_line = raw_line.strip()

                if not stripped_line:
                    rejected_records += 1
                    reject_record(
                        database_path,
                        source_file,
                        batch_id,
                        line_number,
                        "Empty input line",
                        raw_line,
                    )
                    continue

                try:
                    raw_event = json.loads(stripped_line)
                except json.JSONDecodeError as error:
                    rejected_records += 1
                    reject_record(
                        database_path,
                        source_file,
                        batch_id,
                        line_number,
                        f"Invalid JSON: {error.msg}",
                        raw_line,
                    )
                    continue

                try:
                    normalised_event = normalise_event(raw_event)
                except ValueError as error:
                    rejected_records += 1
                    reject_record(
                        database_path,
                        source_file,
                        batch_id,
                        line_number,
                        str(error),
                        raw_line,
                    )
                    continue

                if normalised_event["source_type"] != source_type:
                    rejected_records += 1
                    reject_record(
                        database_path,
                        source_file,
                        batch_id,
                        line_number,
                        "Event source_type does not match source filename",
                        raw_line,
                    )
                    continue

                saved = save_security_event(
                    database_path=database_path,
                    event=normalised_event,
                    source_file=source_file.name,
                    batch_id=batch_id,
                    raw_event=raw_event,
                )

                if saved:
                    accepted_records += 1
                else:
                    rejected_records += 1
                    reject_record(
                        database_path,
                        source_file,
                        batch_id,
                        line_number,
                        "Duplicate source event",
                        raw_line,
                    )

        status = (
            "completed"
            if rejected_records == 0
            else "completed_with_rejections"
        )

    except OSError:
        complete_import_batch(
            database_path,
            batch_id,
            total_records,
            accepted_records,
            rejected_records,
            "failed",
        )
        raise

    complete_import_batch(
        database_path,
        batch_id,
        total_records,
        accepted_records,
        rejected_records,
        status,
    )

    return {
        "batch_id": batch_id,
        "source_file": source_file.name,
        "source_type": source_type,
        "total_records": total_records,
        "accepted_records": accepted_records,
        "rejected_records": rejected_records,
        "status": status,
    }
