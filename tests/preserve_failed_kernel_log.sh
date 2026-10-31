#!/bin/bash
# Keep the complete raw output for failed kernel-suite boots, including misses.
# The gate is serialized, so pruning cannot race another precommit run.
preserve_failed_kernel_log() {
    local source_log="$1" stage="$2" rep="$3" destination
    if ! mkdir -p "$FAILED_KERNEL_LOG_DIR"; then
        echo "       raw log: $source_log (could not create archive directory)"
        return 0
    fi
    if ! destination=$(mktemp "$FAILED_KERNEL_LOG_DIR/${stage}-rep${rep}-$(date +%Y%m%d_%H%M%S)-$$-XXXXXX.log"); then
        echo "       raw log: $source_log (could not reserve archive path)"
        return 0
    fi
    if ! mv -- "$source_log" "$destination"; then
        rm -f -- "$destination"
        echo "       raw log: $source_log (could not move to archive)"
        return 0
    fi
    echo "       raw log: $destination"

    # Bound retained logs across runs. Names contain no whitespace; use NUL
    # records so a worktree path with spaces remains safe.
    local old_log
    while IFS= read -r -d '' old_log; do
        rm -f -- "$old_log"
    done < <(find "$FAILED_KERNEL_LOG_DIR" -maxdepth 1 -type f -name '*.log' \
        ! -samefile "$destination" -printf '%T@ %p\0' | sort -z -nr \
        | tail -z -n +20 | cut -z -d ' ' -f 2-)
}
