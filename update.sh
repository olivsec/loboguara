#!/bin/bash

REPO_URL="https://github.com/olivsec/loboguara.git"
TEMP_DIR="/tmp/loboguara"
INSTALL_DIR="/opt/loboguara"
EXCLUDE_FILE="server/app/config.py"
MODELS_FILE="$INSTALL_DIR/app/models.py"

error_exit() {
    echo "$1"
    exit 1
}

echo "Cloning repository to temporary directory..."
git clone "$REPO_URL" "$TEMP_DIR" || error_exit "Failed to clone repository!"

MODEL_CHANGED=false
if ! diff "$TEMP_DIR/server/app/models.py" "$MODELS_FILE" > /dev/null; then
    MODEL_CHANGED=true
fi

echo "Updating files..."
rsync -av --exclude "$(basename "$EXCLUDE_FILE")" "$TEMP_DIR/server/" "$INSTALL_DIR" || error_exit "Failed to update files!"

echo "Changing ownership of files to 'loboguara'..."
chown -R loboguara:loboguara "$INSTALL_DIR" || error_exit "Failed to change ownership!"

echo "Cleaning up temporary files..."
rm -rf "$TEMP_DIR"

if [ "$MODEL_CHANGED" = true ]; then
    echo "Models have been updated. Running database migrations..."
    sudo -u loboguara bash -c "source $INSTALL_DIR/venv/bin/activate && cd $INSTALL_DIR && flask db migrate -m 'Auto migration' && flask db upgrade" || error_exit "Failed to update database!"
fi

echo "Update completed successfully!"
