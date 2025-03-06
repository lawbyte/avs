#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Utility module for AVS
Provides common helper functions
"""

import os
import json
import hashlib
from datetime import datetime
from rich.console import Console

console = Console()

def calculate_md5(file_path):
    """Calculate MD5 hash of a file"""
    hash_md5 = hashlib.md5()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except Exception as e:
        console.print(f"[bold red]Error calculating MD5: {str(e)}[/bold red]")
        return None

def calculate_sha256(file_path):
    """Calculate SHA256 hash of a file"""
    hash_sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    except Exception as e:
        console.print(f"[bold red]Error calculating SHA256: {str(e)}[/bold red]")
        return None

def get_file_metadata(file_path):
    """Get file metadata"""
    try:
        stat_info = os.stat(file_path)
        return {
            "path": file_path,
            "size": stat_info.st_size,
            "created": datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
            "modified": datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
            "accessed": datetime.fromtimestamp(stat_info.st_atime).isoformat(),
            "md5": calculate_md5(file_path),
            "sha256": calculate_sha256(file_path)
        }
    except Exception as e:
        console.print(f"[bold red]Error getting file metadata: {str(e)}[/bold red]")
        return None

def save_json(data, output_path):
    """Save data to a JSON file"""
    try:
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=4)
        return True
    except Exception as e:
        console.print(f"[bold red]Error saving JSON: {str(e)}[/bold red]")
        return False

def load_json(file_path):
    """Load data from a JSON file"""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        console.print(f"[bold red]Error loading JSON: {str(e)}[/bold red]")
        return None

def ensure_dir(directory):
    """Ensure that a directory exists"""
    if not os.path.exists(directory):
        os.makedirs(directory)
        return True
    return False
