#!/bin/bash
# run_demo.sh — оркестратор лабораторной работы №10.
# Выполняет все этапы задания по порядку (шаги 1-17) внутри контейнера.
set -u
. /opt/lab/scripts/common.sh

echo "################################################################"
echo "# Лабораторная работа №10. Управление доступом к объектам ОС Linux"
echo "# Контейнер: Ubuntu 24.04, текущий пользователь: $(id)"
echo "# Ядро: $(uname -r)"
echo "################################################################"

t0=$SECONDS

bash "$SCRIPTS/setup.sh"            # шаги 1-11: группы, пользователи, sudo, папки
bash "$SCRIPTS/create_files.sh"     # шаги 12-13: смена пользователя, файлы file11-file55
bash "$SCRIPTS/check_matrix.sh"     # шаг 14: матрица доступа -> demo_output/matrix.txt
bash "$SCRIPTS/process_control.sh"  # шаг 15: запуск filex5 и kill -> demo_output/process_control.txt
bash "$SCRIPTS/check_dirs.sh"       # шаг 16: операции над папками -> demo_output/dirs.txt
bash "$SCRIPTS/cleanup.sh"          # шаг 17: удаление всего созданного

echo
echo "################################################################"
echo "# Готово. Время выполнения: $((SECONDS - t0)) c."
echo "# Артефакты в demo_output/: $(ls "$DEMO" | sort | tr '\n' ' ')"
echo "################################################################"

# чтобы файлы на хосте не принадлежали root (demo_output смонтирован с хоста)
chown -R "${HOST_UID:-1000}:${HOST_GID:-1000}" "$DEMO" 2>/dev/null
exit 0
