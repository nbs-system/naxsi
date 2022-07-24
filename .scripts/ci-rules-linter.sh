#!/bin/sh
# SPDX-FileCopyrightText: 2022 wargio <deroad@libero.it>
# SPDX-License-Identifier: LGPL-3.0-only
RULE_FOLDER="$1"

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
TMP_DIR="$SCRIPT_DIR/.tmp"
RET_VAL=0

if [ -z "$RULE_FOLDER" ]; then
    echo "usage: $0 <rule folder>"
    echo "example: $0 naxsi_rules/blocking"
    exit 1
fi

if [[ -d "$TMP_DIR" ]]; then
    rm -rf "$TMP_DIR"
fi

mkdir "$TMP_DIR" || exit 1
for FILE in $(ls "$RULE_FOLDER/"*.rules); do
    FILENAME=$(basename $FILE)
    echo "Linter: $FILE"
    python "$SCRIPT_DIR/naxsi-lint.py" -r "$FILE" -o "$TMP_DIR/$FILENAME" || exit 1
    DIFF=$(diff -u "$FILE" "$TMP_DIR/$FILENAME")
    if [[ ! -z "$DIFF" ]]; then
        diff -u --color=auto "$FILE" "$TMP_DIR/$FILENAME"
        RET_VAL=1
    fi
done

rm -rf "$TMP_DIR"
exit $RET_VAL