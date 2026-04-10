from collections import Counter
from pathlib import Path
from typing import Dict, List, Tuple
from sklearn.model_selection import train_test_split
from .rf_training_mapping import map_cicids2019_labels
import pandas as pd

## Imported dataset from CICIDS2019, with utilities to prepare training data for the Random Forest classifier.

_LABEL_COLUMN_CANDIDATES = ("Label", "label", "Class", "class")
DEFAULT_MAX_ROWS = 150000 ##150k is a good in-between to prevent OOM while using a good sample size. 


def _find_label_column(columns: List[str]) -> str:
	normalized_to_original = {
		str(column).strip().lower(): str(column)
		for column in columns
	}
	for candidate in _LABEL_COLUMN_CANDIDATES:
		match = normalized_to_original.get(candidate.lower())
		if match:
			return match
	raise ValueError(
		"Dataset must include a label column. Supported names: Label, label, Class, class"
	)


def _read_and_normalize_csv(csv_path: Path, nrows: int | None = None) -> pd.DataFrame:
	dataframe = pd.read_csv(csv_path, low_memory=False, nrows=nrows)
	dataframe.columns = [str(column).strip() for column in dataframe.columns]
	return dataframe


def load_cicids2019_dataframe(dataset_path: str | None = None, max_rows: int | None = None) -> pd.DataFrame:
	"""Load CICIDS2019 dataset from a CSV file or directory of CSV files."""
	if not dataset_path:
		raise ValueError("REQUIRED: dataset_path - MUST POINT TO: CICIDS CSV file/directory.")

	selected_path = Path(dataset_path)
	if not selected_path.exists():
		raise FileNotFoundError(f"Dataset not found at path: {selected_path}")

	row_limit = max_rows if (max_rows and max_rows > 0) else None
	if row_limit is None and selected_path.is_dir():
		# Prevent container OOM on very large folders when no explicit cap is provided.
		row_limit = DEFAULT_MAX_ROWS

	if selected_path.is_file():
		return _read_and_normalize_csv(selected_path, nrows=row_limit)

	csv_files = sorted(selected_path.rglob("*.csv"))
	if not csv_files:
		raise ValueError(f"No CSV files found under directory: {selected_path}")

	# When a row cap is set for a directory, distribute reads across files so
	# training does not overfit to whichever file is first in sort order.
	per_file_limits: Dict[Path, int] = {}
	if row_limit is not None:
		file_count = len(csv_files)
		base_rows = row_limit // file_count
		remainder = row_limit % file_count
		for index, csv_file in enumerate(csv_files):
			per_file_limits[csv_file] = base_rows + (1 if index < remainder else 0)

	frames: List[pd.DataFrame] = []
	errors: List[str] = []
	rows_collected = 0
	for csv_file in csv_files:
		remaining_rows = None
		if row_limit is not None:
			remaining_rows = per_file_limits.get(csv_file, 0)
			if remaining_rows <= 0:
				continue
		try:
			frame = _read_and_normalize_csv(csv_file, nrows=remaining_rows)
			if frame.empty:
				continue
			frames.append(frame)
			rows_collected += len(frame)
		except Exception as exc:
			errors.append(f"{csv_file}: {exc}")

	if not frames:
		error_preview = "; ".join(errors[:3])
		raise ValueError(f"Failed to read any CSV files from {selected_path}. {error_preview}")

	combined = pd.concat(frames, ignore_index=True, sort=False)
	if row_limit is not None and len(combined) > row_limit:
		combined = combined.iloc[:row_limit].copy()
	if max_rows is None and selected_path.is_dir() and len(combined) >= DEFAULT_MAX_ROWS:
		raise ValueError(
			f"Dataset directory is large; loaded first {DEFAULT_MAX_ROWS} rows only. "
			"ADJUST max_rows: Change payload size in /rf/train. MODIFY: DEFAULT_MAX_ROWS to increase row cap."
		)
	return combined


def _row_to_log_dict(row: Dict) -> Dict:
	serialized = {}
	for key, value in row.items():
		if pd.isna(value):
			continue
		serialized[str(key)] = value
	return serialized


def _to_training_pairs(df: pd.DataFrame, label_col: str) -> List[Tuple[Dict, str]]:
	data: List[Tuple[Dict, str]] = []
	for _, row in df.iterrows():
		row_dict = row.to_dict()
		mapped_label = row_dict.pop("mapped_label")
		row_dict.pop(label_col, None)
		data.append((_row_to_log_dict(row_dict), mapped_label))
	return data


def prepare_cicids2019_training_bundle(
	dataset_path: str,
	seed: int = 42,
	min_samples_per_class: int = 50,
	max_rows: int | None = None,
) -> Dict:
	"""Build a stratified 70/15/15 training bundle from CICIDS2019."""
	df = load_cicids2019_dataframe(dataset_path, max_rows=max_rows)

	if df.empty:
		raise ValueError("Dataset is empty")

	label_col = _find_label_column(df.columns.tolist())
	working = df.copy()
	working[label_col] = working[label_col].fillna("").astype(str)
	working["mapped_label"] = map_cicids2019_labels(working[label_col].tolist())
	working = working[working["mapped_label"] != "unknown"]

	if working.empty:
		raise ValueError("No usable labels found after CICIDS mapping")

	label_counts = Counter(working["mapped_label"].tolist())
	too_small = {k: v for k, v in label_counts.items() if v < min_samples_per_class}
	if too_small:
		raise ValueError(
			f"Not enough samples for classes {too_small}. "
			f"Increase dataset size or reduce min_samples_per_class."
		)

	train_df, temp_df = train_test_split(
		working,
		test_size=0.30,
		random_state=seed,
		stratify=working["mapped_label"],
	)
	val_df, test_df = train_test_split(
		temp_df,
		test_size=0.50,
		random_state=seed,
		stratify=temp_df["mapped_label"],
	)

	return {
		"dataset_path": str(Path(dataset_path)),
		"label_column": label_col,
		"seed": seed,
		"split_policy": "70/15/15_stratified",
		"class_distribution": dict(label_counts),
		"train_data": _to_training_pairs(train_df, label_col),
		"validation_data": _to_training_pairs(val_df, label_col),
		"test_data": _to_training_pairs(test_df, label_col),
	}

