#!/usr/bin/env bash

CONFIG_FILE="server/app/config.py"
INIT_FILE="/opt/loboguara/app/__init__.py"
INSTALL_DIR="/opt/loboguara"

error_exit() {
    echo "$1"
    exit 1
}

if [ ! -f "$CONFIG_FILE" ]; then
    error_exit "Configuration file $CONFIG_FILE not found!"
fi

echo "Checking variables in the configuration file..."

# need to modify variables referencing services with localhost
sed -i -r "s/(SQLALCHEMY_DATABASE_URI = 'postgresql:\/\/guarauser:YOUR_PASSWORD_HERE@)(localhost)(\/guaradb\?sslmode=disable')/\1postgres\3/" "$CONFIG_FILE"

DB_URI=$(grep -oP 'SQLALCHEMY_DATABASE_URI\s*=\s*'\''\K[^'\'']+' "$CONFIG_FILE")
MAIL_SERVER=$(grep -oP 'MAIL_SERVER\s*=\s*'\''\K[^'\'']+' "$CONFIG_FILE")
MAIL_PORT=$(grep -oP 'MAIL_PORT\s*=\s*\K[0-9]+' "$CONFIG_FILE")
MAIL_USE_TLS=$(grep -oP 'MAIL_USE_TLS\s*=\s*\K(True|False)' "$CONFIG_FILE")
MAIL_USERNAME=$(grep -oP 'MAIL_USERNAME\s*=\s*'\''\K[^'\'']+' "$CONFIG_FILE")
MAIL_PASSWORD=$(grep -oP 'MAIL_PASSWORD\s*=\s*'\''\K[^'\'']+' "$CONFIG_FILE")
MAIL_DEFAULT_SENDER=$(grep -oP 'MAIL_DEFAULT_SENDER\s*=\s*'\''\K[^'\'']+' "$CONFIG_FILE")
API_ACCESS_TOKEN=$(grep -oP 'API_ACCESS_TOKEN\s*=\s*'\''\K[^'\'']+' "$CONFIG_FILE")
API_URL=$(grep -oP 'API_URL\s*=\s*'\''\K[^'\'']+' "$CONFIG_FILE")
CHROME_DRIVER_PATH=$(grep -oP 'CHROME_DRIVER_PATH\s*=\s*'\''\K[^'\'']+' "$CONFIG_FILE")
GOOGLE_CHROME_PATH=$(grep -oP 'GOOGLE_CHROME_PATH\s*=\s*'\''\K[^'\'']+' "$CONFIG_FILE")
FFUF_PATH=$(grep -oP 'FFUF_PATH\s*=\s*'\''\K[^'\'']+' "$CONFIG_FILE")
SUBFINDER_PATH=$(grep -oP 'SUBFINDER_PATH\s*=\s*'\''\K[^'\'']+' "$CONFIG_FILE")

# SKIP, otherwise the build process will fail
#echo "Checking database connection and permissions..."
#psql -h postgres "$DB_URI" -c "\dt" > /dev/null 2>&1 || error_exit "Failed to connect to the database!"

#EXTENSION=$(psql -h postgres "$DB_URI" -c "SELECT * FROM pg_extension WHERE extname = 'pg_trgm';" | grep pg_trgm)
#if [ -z "$EXTENSION" ]; then
#    error_exit "pg_trgm extension not found!"
#fi

echo "Checking email settings..."
if [ -z "$MAIL_SERVER" ] || [ -z "$MAIL_PORT" ] || [ -z "$MAIL_USERNAME" ] || [ -z "$MAIL_PASSWORD" ] || [ -z "$MAIL_DEFAULT_SENDER" ]; then
    error_exit "Incomplete email configuration!"
fi

echo "Checking access to the Lobo Guará API..."
API_RESPONSE=$(curl -s -H "x-access-tokens: $API_ACCESS_TOKEN" "$API_URL/verify_token")
if [[ "$API_RESPONSE" != *"Token is valid"* ]]; then
    error_exit "Invalid or expired token for the Lobo Guará API!"
fi

echo "Checking binaries..."
for path in "$CHROME_DRIVER_PATH" "$GOOGLE_CHROME_PATH" "$FFUF_PATH" "$SUBFINDER_PATH"; do
    if [ ! -x "$path" ]; then
        error_exit "Binary $path not found or not executable!"
    fi
done

echo "Installing in the directory $INSTALL_DIR..."
sudo mkdir -p "$INSTALL_DIR" || error_exit "Failed to create directory $INSTALL_DIR!"
sudo cp -R server/* "$INSTALL_DIR" || error_exit "Failed to copy files to $INSTALL_DIR!"

echo "Creating virtual environment..."
python3.12 -m venv "$INSTALL_DIR/venv" || error_exit "Failed to create virtual environment!"
source "$INSTALL_DIR/venv/bin/activate"
pip install -r "$INSTALL_DIR/requirements.txt" || error_exit "Failed to install dependencies!"

echo "Compiling realtime.proto..."
python3.12 -m grpc_tools.protoc -I"$INSTALL_DIR" --python_out="$INSTALL_DIR" --grpc_python_out="$INSTALL_DIR" "$INSTALL_DIR/realtime.proto" || error_exit "Failed to compile realtime.proto!"

export FLASK_APP="$INSTALL_DIR/run.py"

echo "Initializing the database..."
cd "$INSTALL_DIR" || error_exit "Failed to access the installation directory!"

flask db init || error_exit "Failed to initialize the database!"
flask db migrate -m "Initial migration." || error_exit "Failed to create migration!"
flask db upgrade || error_exit "Failed to upgrade the database!"

echo "Populating timezones table..."

psql -h postgres "$DB_URI" <<EOF || error_exit "Failed to populate timezones table!"
DO
\$\$
BEGIN
    -- Remove duplicate timezone if exists
    DELETE FROM timezones WHERE name = '(UTC) Monróvia, Reiquiavique';

    -- Insert or update timezones
    INSERT INTO timezones (name, pytz_name)
    VALUES
        ('(UTC-12:00) International Date Line West', 'Etc/GMT+12'),
        ('(UTC-11:00) Coordinated Universal Time-11', 'Etc/GMT+11'),
        ('(UTC-10:00) Hawaii', 'Pacific/Honolulu'),
        ('(UTC-09:00) Alaska', 'America/Anchorage'),
        ('(UTC-08:00) Pacific Time (US & Canada)', 'America/Los_Angeles'),
        ('(UTC-07:00) Mountain Time (US & Canada)', 'America/Denver'),
        ('(UTC-06:00) Central Time (US & Canada)', 'America/Chicago'),
        ('(UTC-05:00) Eastern Time (US & Canada)', 'America/New_York'),
        ('(UTC-04:00) Atlantic Time (Canada)', 'America/Halifax'),
        ('(UTC-03:00) Brasília', 'America/Sao_Paulo'),
        ('(UTC-02:00) Mid-Atlantic', 'Etc/GMT+2'),
        ('(UTC-01:00) Azores', 'Atlantic/Azores'),
        ('(UTC+00:00) Monróvia, Reiquiavique', 'UTC'),
        ('(UTC+01:00) West Central Africa', 'Africa/Lagos'),
        ('(UTC+02:00) Cairo', 'Africa/Cairo'),
        ('(UTC+03:00) Moscow, St. Petersburg, Volgograd', 'Europe/Moscow'),
        ('(UTC+04:00) Abu Dhabi, Muscat', 'Asia/Dubai'),
        ('(UTC+05:00) Islamabad, Karachi', 'Asia/Karachi'),
        ('(UTC+06:00) Astana, Dhaka', 'Asia/Dhaka'),
        ('(UTC+07:00) Bangkok, Hanoi, Jakarta', 'Asia/Bangkok'),
        ('(UTC+08:00) Beijing, Chongqing, Hong Kong, Urumqi', 'Asia/Shanghai'),
        ('(UTC+09:00) Tokyo, Osaka, Sapporo', 'Asia/Tokyo'),
        ('(UTC+10:00) Brisbane', 'Australia/Brisbane'),
        ('(UTC+11:00) Solomon Islands, New Caledonia', 'Pacific/Guadalcanal'),
        ('(UTC+12:00) Fiji, Marshall Islands', 'Pacific/Fiji')
    ON CONFLICT (name) DO UPDATE SET pytz_name = EXCLUDED.pytz_name;
END
\$\$;
EOF


echo "Uncommenting the call to init_timezones() in the __init__.py file..."
sed -i '/# init_timezones()/s/^# //' "$INIT_FILE" || error_exit "Failed to uncomment init_timezones()"

echo "Creating symbolic link to wafw00f..."
sudo ln -sf /opt/loboguara/venv/bin/wafw00f /opt/loboguara/bin/wafw00f

echo "Creating the service user 'loboguara'..."
if id "loboguara" &>/dev/null; then
    echo "User 'loboguara' already exists."
else
    sudo useradd -r -m -d /home/loboguara -s /bin/false loboguara || error_exit "Failed to create the service user 'loboguara'."
fi

echo "Setting 'loboguara' as the owner of the directory /opt/loboguara/..."
sudo chown -R loboguara:loboguara /opt/loboguara || error_exit "Failed to change ownership of the directory to 'loboguara'."

echo "Adjusting permissions..."
sudo chmod -R 750 /opt/loboguara || error_exit "Failed to adjust permissions."

echo "Adding dashboard update to cron..."
cron_job="*/1 * * * * /opt/loboguara/venv/bin/python /opt/loboguara/update_dashboard_metrics.py > /dev/null 2>&1"

( sudo crontab -u loboguara -l 2>/dev/null | grep -qF "$cron_job" ) || ( sudo crontab -u loboguara -l 2>/dev/null; echo "$cron_job" ) | sudo crontab -u loboguara -

echo "Cron job added to loboguara's crontab."


sudo chmod a+x /opt/loboguara/start.sh

echo "

                                                                                          
                                                                                          
                                                                                          
                                                                                          
                                              .                                           
                                             :%#       .                                  
                                            =@@@*     *+                                  
                                          -#@@@@@=  -%@*                                  
                                        -#@@#@@%@%#@@@@+                                  
                                      -#@@#+*@%=@@@@@@@:                                  
                                    :#@@#+=+%@*:%@@@@@*                                   
                                  -#@@@*==+%@%::#%#@@%.                                   
                            .:-=*%@@@@#=+#@@#-::-=:-*@%=                                  
                            .-+**###@@*#@@@*-::::::::-%@-                                 
                               :=+#%@@@@@#=-----+**+-:=@%-                                
                            :*%@@@@@@@%*=--------*%@%-:=%@*-                              
                          :#@@@@@@@@%*++======++---------+#@%*=:                          
                         *@@@@@@@@@@@@@@@@@%*+=-------------+*%@@#          ::-:.         
        -+*+:           #@@@@@@@@@@@@@@%*+--------------------=%@*         -==---.        
       +@@@@@+         *@@@@@@@@@@@@%#+-------=++***********#%@%-          -====-.        
       =@@@@@=        -@@@@@@@@@@@%*==------=++#@@@**********+:             .-*-          
        .===.         #@@%+#@@@@@#=======---=*%@@@@.                         -@=          
         :#:          @@*.#@@@@@*===========%@@@@@@*                         =@-          
         -@=          %= +@@@@@+==========+%@@@@#@@@+                        +@:          
         .@*          -  %@@@@#=*#========%@@@%=*@@@@#:                      %%           
          #%.           .@@@@@+%@+=======*@@@@=-=@@@@@@*-                   =@-           
          :@+            %@@@@%@@========*@@@*---+%@@@@@@%*=:.             :@#            
           +@=           *@@@@@@@========*@@@=--+==#@@@@@@@@@@%#*++==-.   .%%.            
            *@-          :@@@@@@@*========%@@====%#++*#@@@@@@@@@%*+-:     +#.             
             *@=          =@@@*@@%========*@@+===*@@@@%%%@@@@@@@@%+-.                     
              -%*          =@@:-@@#==+++===+%#====*@@@@@@@@@@@@@@@@@@%#*+++++*#*.         
               ..           -%. -@@#+++++++++**====+%@@@@@@@@@@@@@@@@@@@@@@@@#-           
      ==+++++++++++++++++++++*+++*@@%*+++++++++++++==+#@@@@@@@@@@@@@@@@@@@@%*+======.     
      =++++++++++++++++++++++++++++++++--------------::-=+++++++++++++++++++++++++++.     

Installation completed successfully!
The application can now only be started by the user 'loboguara'.
"

