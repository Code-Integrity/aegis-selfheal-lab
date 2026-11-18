#!/bin/sh
set -e
rm -rf /app/critical_data/*
cp -r /app/clean_backup/* /app/critical_data/
exec python3 /app/app.py
