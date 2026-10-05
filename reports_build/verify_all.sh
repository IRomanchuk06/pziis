#!/bin/bash
# Контрольный прогон демонстраций всех лаб одной командой каждая
cd /home/ivan/PRs/bsuir_7/pziis
LOG=reports_build/verify_all.log
: > "$LOG"
for n in 1 2 3 4 5 6 7 8 10 11 12; do
  echo "===== lab_$n: start $(date +%H:%M:%S) =====" >> "$LOG"
  if (cd "lab_$n" && timeout 1200 ./run.sh >> /tmp/verify_lab_$n.log 2>&1); then
    echo "lab_$n: PASS (exit 0)" >> "$LOG"
  else
    echo "lab_$n: FAIL (exit $?)" >> "$LOG"
  fi
done
echo "===== DONE $(date +%H:%M:%S) =====" >> "$LOG"
