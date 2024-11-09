use ssh2::Session;
use std::net::TcpStream;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use std::fs::{self, OpenOptions};
use std::io::{self, Write, BufWriter};
use std::path::Path;
use std::{thread, time};

#[derive(Serialize, Deserialize, Clone)]
struct TunnelConfig {
    id: usize,
    name: String,
    username: String,
    hostname: String,
    local_port: u16,
    remote_port: u16,
    #[serde(default)]
    use_key_auth: bool,
    #[serde(default)]
    key_path: Option<String>,
    #[serde(default = "default_timeout")]
    timeout: u64,
    #[serde(default)]
    auto_connect: bool,
    #[serde(default)]
    saved_password: Option<String>,
}

fn default_timeout() -> u64 {
    30
}

struct SSHManager {
    tunnels: HashMap<usize, TunnelConfig>,
    log_writer: BufWriter<std::fs::File>,
}

impl SSHManager {
    fn new() -> Self {
        let log_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open("ssh_tunnel_manager.log")
            .expect("Не удалось открыть файл лога");

        let mut manager = SSHManager {
            tunnels: HashMap::new(),
            log_writer: BufWriter::new(log_file),
        };
        manager.load_tunnels();
        manager
    }

    fn log(&mut self, message: &str) {
        writeln!(self.log_writer, "{}", message).expect("Не удалось записать в лог");
        self.log_writer.flush().unwrap();
    }

    fn add_tunnel(&mut self, config: TunnelConfig) {
        if self.tunnels.contains_key(&config.id) {
            println!("Туннель с ID {} уже существует!", config.id);
            self.log(&format!("Ошибка: Туннель с ID {} уже существует", config.id));
        } else {
            self.tunnels.insert(config.id, config.clone());
            println!("Туннель '{}' добавлен с ID: {}", config.name, config.id);
            self.log(&format!("Туннель добавлен: ID={} Имя='{}'", config.id, config.name));
            self.save_tunnels();
        }
    }

    fn remove_tunnel(&mut self, id: usize) {
        if self.tunnels.remove(&id).is_some() {
            println!("Туннель с ID {} удален", id);
            self.log(&format!("Туннель удален: ID={}", id));
            self.save_tunnels();
        } else {
            println!("Туннель с ID {} не существует!", id);
            self.log(&format!("Ошибка: Туннель с ID {} не существует", id));
        }
    }

    fn list_tunnels(&self) {
        if self.tunnels.is_empty() {
            println!("Туннели не настроены.");
        } else {
            for (id, config) in &self.tunnels {
                println!("ID: {}, Имя: '{}', Хост: {}, Локальный порт: {}, Удаленный порт: {}, Аутентификация: {}, Автоподключение: {}",
                         id, config.name, config.hostname, config.local_port, config.remote_port,
                         if config.use_key_auth { "SSH ключ" } else { "Пароль" },
                         if config.auto_connect { "Вкл" } else { "Выкл" });
            }
        }
    }

    fn connect_tunnel(&mut self, id: usize) {
        if let Some(config) = self.tunnels.get(&id) {
            println!("Попытка подключения к '{} ({})'...", config.name, config.hostname);
            for _ in 0..3 {
                print!(".");
                io::stdout().flush().unwrap();
                thread::sleep(time::Duration::from_millis(500));
            }

            let connect_result = match TcpStream::connect_timeout(
                &format!("{}:22", config.hostname).parse().unwrap(),
                time::Duration::from_secs(config.timeout),
            ) {
                Ok(stream) => {
                    let mut session = Session::new().unwrap();
                    session.set_tcp_stream(stream);
                    session.handshake().unwrap();

                    if config.use_key_auth {
                        if let Some(key_path) = &config.key_path {
                            session.userauth_pubkey_file(&config.username, None, Path::new(key_path), None)
                        } else {
                            println!("Путь к SSH-ключу не указан для туннеля с ID {}", id);
                            self.log(&format!("Ошибка: Путь к SSH-ключу не указан для ID {}", id));
                            return;
                        }
                    } else {
                        let password = if let Some(saved_password) = &config.saved_password {
                            saved_password.clone()
                        } else {
                            println!("\nВведите пароль для подключения:");
                            read_password()
                        };

                        session.userauth_password(&config.username, &password)
                    }
                }
                Err(e) => {
                    println!("\n❌ Не удалось подключиться: {}", e);
                    self.log(&format!("Ошибка подключения к {}: {}", config.hostname, e));
                    return;
                }
            };

            match connect_result {
                Ok(_) => {
                    println!("\n✅ Успешное подключение!");
                    self.log(&format!("Успешное подключение к {} ({})", config.name, config.hostname));
                }
                Err(e) => {
                    println!("\n❌ Ошибка аутентификации: {}", e);
                    self.log(&format!("Ошибка аутентификации: {} для {}", e, config.hostname));
                }
            }
        } else {
            println!("Туннель с ID {} не существует!", id);
            self.log(&format!("Ошибка: Туннель с ID {} не существует", id));
        }
    }

    fn connect_all(&mut self) {
        for id in self.tunnels.keys().cloned().collect::<Vec<usize>>() {
            self.connect_tunnel(id);
        }
    }

    fn search_tunnels(&self, query: &str) {
        let mut found = false;
        for (id, config) in &self.tunnels {
            if config.name.contains(query) || config.hostname.contains(query) {
                println!("Найден туннель - ID: {}, Имя: '{}', Хост: {}", id, config.name, config.hostname);
                found = true;
            }
        }
        if !found {
            println!("Туннели, соответствующие запросу '{}', не найдены.", query);
        }
    }

    fn save_tunnels(&self) {
        let data = serde_json::to_string(&self.tunnels).unwrap();
        fs::write("tunnels.json", data).expect("Не удалось сохранить настройки туннеля");
        println!("Настройки туннелей сохранены.");
    }

    fn load_tunnels(&mut self) {
        if let Ok(data) = fs::read_to_string("tunnels.json") {
            self.tunnels = serde_json::from_str(&data).unwrap_or_default();
            println!("Настройки туннелей загружены.");
            self.log("Настройки туннелей загружены.");

            let auto_connect_ids: Vec<usize> = self.tunnels
                .iter()
                .filter(|(_, config)| config.auto_connect)
                .map(|(id, _)| *id)
                .collect();

            for id in auto_connect_ids {
                println!("Автоподключение к туннелю с ID {}", id);
                self.connect_tunnel(id);
            }
        }
    }


    fn export_config(&self, filename: &str) {
        let data = serde_json::to_string_pretty(&self.tunnels).unwrap();
        fs::write(filename, data).expect("Не удалось экспортировать конфигурацию");
        println!("Конфигурация экспортирована в файл '{}'", filename);
    }

    fn import_config(&mut self, filename: &str) {
        if let Ok(data) = fs::read_to_string(filename) {
            let imported_tunnels: HashMap<usize, TunnelConfig> = serde_json::from_str(&data).unwrap_or_default();
            for (id, config) in imported_tunnels {
                self.tunnels.insert(id, config.clone());
                println!("Туннель '{}' добавлен из импортированной конфигурации", config.name);
                self.log(&format!("Туннель '{}' импортирован", config.name));
            }
            self.save_tunnels();
        } else {
            println!("Ошибка: не удалось найти файл '{}'", filename);
        }
    }
}

fn main() {
    let mut manager = SSHManager::new();

    loop {
        println!("\nВыберите команду:");
        println!("1. Добавить туннель");
        println!("2. Удалить туннель");
        println!("3. Подключиться к туннелю");
        println!("4. Подключиться ко всем туннелям");
        println!("5. Показать список туннелей");
        println!("6. Поиск туннеля");
        println!("7. Экспортировать конфигурацию");
        println!("8. Импортировать конфигурацию");
        println!("9. Выйти");

        print!("Введите номер команды: ");
        io::stdout().flush().unwrap();

        let mut command = String::new();
        io::stdin().read_line(&mut command).expect("Ошибка чтения команды");

        match command.trim() {
            "1" => {
                println!("Введите ID туннеля:");
                let id = read_usize();
                println!("Введите имя туннеля:");
                let name = read_string();
                println!("Введите имя пользователя:");
                let username = read_string();
                println!("Введите адрес хоста:");
                let hostname = read_string();
                println!("Введите локальный порт:");
                let local_port = read_u16();
                println!("Введите удаленный порт:");
                let remote_port = read_u16();

                println!("Использовать SSH ключ для аутентификации? (y/n): ");
                let use_key_auth = read_optional_string().to_lowercase() == "y";

                let key_path = if use_key_auth {
                    println!("Введите путь к SSH-ключу (или оставьте пустым): ");
                    let path = read_optional_string();
                    if path.is_empty() { None } else { Some(path) }
                } else {
                    None
                };

                println!("Установить тайм-аут подключения (в секундах, по умолчанию 30): ");
                let timeout = read_optional_u64().unwrap_or(30);

                println!("Включить автоподключение? (y/n): ");
                let auto_connect = read_optional_string().to_lowercase() == "y";

                println!("Сохранить пароль для автоматического входа? (y/n): ");
                let saved_password = if !use_key_auth && read_optional_string().to_lowercase() == "y" {
                    println!("Введите пароль для сохранения:");
                    Some(read_password())
                } else {
                    None
                };

                manager.add_tunnel(TunnelConfig {
                    id,
                    name,
                    username,
                    hostname,
                    local_port,
                    remote_port,
                    use_key_auth,
                    key_path,
                    timeout,
                    auto_connect,
                    saved_password,
                });
            }
            "2" => {
                println!("Введите ID туннеля для удаления:");
                let id = read_usize();
                manager.remove_tunnel(id);
            }
            "3" => {
                println!("Введите ID туннеля для подключения:");
                let id = read_usize();
                manager.connect_tunnel(id);
            }
            "4" => {
                println!("Подключение ко всем туннелям...");
                manager.connect_all();
            }
            "5" => manager.list_tunnels(),
            "6" => {
                println!("Введите имя или хост для поиска:");
                let query = read_string();
                manager.search_tunnels(&query);
            }
            "7" => {
                println!("Введите имя файла для экспорта (например, config.json):");
                let filename = read_string();
                manager.export_config(&filename);
            }
            "8" => {
                println!("Введите имя файла для импорта:");
                let filename = read_string();
                manager.import_config(&filename);
            }
            "9" => {
                println!("Выход из программы.");
                break;
            }
            _ => println!("Неверная команда, попробуйте снова."),
        }
    }
}

fn read_usize() -> usize {
    loop {
        let mut input = String::new();
        io::stdin().read_line(&mut input).expect("Ошибка чтения ввода");
        match input.trim().parse::<usize>() {
            Ok(value) => return value,
            Err(_) => println!("Пожалуйста, введите целое число."),
        }
    }
}

fn read_u16() -> u16 {
    loop {
        let mut input = String::new();
        io::stdin().read_line(&mut input).expect("Ошибка чтения ввода");
        match input.trim().parse::<u16>() {
            Ok(value) => return value,
            Err(_) => println!("Пожалуйста, введите целое число."),
        }
    }
}

fn read_string() -> String {
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Ошибка чтения ввода");
    input.trim().to_string()
}

fn read_optional_string() -> String {
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Ошибка чтения ввода");
    input.trim().to_string()
}

fn read_optional_u64() -> Option<u64> {
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Ошибка чтения ввода");
    if input.trim().is_empty() {
        None
    } else {
        match input.trim().parse::<u64>() {
            Ok(value) => Some(value),
            Err(_) => {
                println!("Пожалуйста, введите целое число.");
                None
            }
        }
    }
}

fn read_password() -> String {
    println!("Введите пароль: ");
    let mut password = String::new();
    io::stdin().read_line(&mut password).expect("Ошибка чтения пароля");
    password.trim().to_string()
}
