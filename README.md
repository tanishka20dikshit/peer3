# SecureProgramming

A comprehensive multi-module Spring Boot application implementing a secure peer-to-peer communication system with WebSocket support, cryptographic security, and distributed server management.

## 🏗️ Architecture Overview

This project implements a **Secure Communication Protocol (SOCP)** system with the following components:

- **Introducer Service**: Bootstrap registry for initial server discovery and registration (startup only)
- **Server Network**: Distributed servers with direct database connections and peer-to-peer communication
- **Client Applications**: Python clients for user interaction
- **Security Layer**: RSA-4096 encryption, RSASSA-PSS signatures, and secure key management

### System Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Python Client │    │   Python Client │    │   Python Client │
│                 │    │                 │    │                 │
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │
          │ WebSocket            │ WebSocket            │ WebSocket
          │ (Encrypted)          │ (Encrypted)          │ (Encrypted)
          │                      │                      │
┌─────────▼───────┐    ┌─────────▼───────┐    ┌─────────▼───────┐
│   Server Node   │    │   Server Node   │    │   Server Node   │
│   (Port 8080)   │    │   (Port 8081)   │    │   (Port 8082)   │
│                 │    │                 │    │                 │
│  ┌─────────────┐│    │  ┌─────────────┐│    │  ┌─────────────┐│
│  │   MySQL     ││    │  │   MySQL     ││    │  │   MySQL     ││
│  │  Database   ││    │  │  Database   ││    │  │  Database   ││
│  │             ││    │  │             ││    │  │             ││
│  │ • Users     ││    │  │ • Users     ││    │  │ • Users     ││
│  │ • Groups    ││    │  │ • Groups    ││    │  │ • Groups    ││
│  │ • Messages  ││    │  │ • Messages  ││    │  │ • Messages  ││
│  └─────────────┘│    │  └─────────────┘│    │  └─────────────┘│
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │
          │ WebSocket            │ WebSocket            │ WebSocket
          │ (Inter-server)       │ (Inter-server)       │ (Inter-server)
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 │
                    ┌─────────────▼─────────────┐
                    │    Introducer Service     │
                    │    (Port 8100)            │
                    │                           │
                    │  • Server Registry        │
                    │  • Bootstrap Discovery    │
                    │  • Peer Authentication    │
                    │                           │
                    │  (Startup Only)           │
                    └───────────────────────────┘
```

### Architecture Flow

1. **Startup Phase**:
   - Server connects to Introducer for registration
   - Introducer assigns server ID and provides peer list
   - Server establishes direct connections with peers

2. **Runtime Phase**:
   - Servers communicate directly via WebSocket
   - Each server maintains its own database connection
   - Introducer is not involved in normal operations

3. **Client Communication**:
   - Clients connect directly to server nodes
   - All business logic runs on server nodes
   - Database operations happen locally on each server

## ✨ Key Features

### 🔐 Security & Cryptography
- **End-to-End Encryption**: RSA-4096 encryption for all communications
- **Digital Signatures**: RSASSA-PSS signatures for message authentication
- **Secure Key Management**: Centralized key distribution and rotation
- **Mutual Authentication**: Server-to-server authentication

### 🌐 Distributed Architecture
- **Peer-to-Peer Network**: Distributed server nodes with direct communication
- **Bootstrap Discovery**: Introducer service for initial server registration and peer discovery
- **Direct Database Access**: Each server maintains its own database connection
- **Fault Tolerance**: Independent server nodes with automatic failover

### 💬 Real-time Communication
- **WebSocket Support**: Real-time bidirectional communication
- **Message Broadcasting**: Efficient message distribution across the network
- **User Presence**: Real-time user online status tracking
- **Group Management**: Multi-user group communication

### 📊 Data Management
- **User Management**: Complete user registration and authentication system
- **Group Management**: Create and manage user groups
- **Message History**: Persistent message storage and retrieval
- **File Transfer**: Secure file sharing capabilities

## 📦 Modules

- **parent** – Project and dependency management (BOM)
- **introducer** – Bootstrap registry service for initial server discovery and registration
- **server** – Distributed server nodes with direct database access and peer-to-peer communication
- **client** – Python client applications for user interaction

## 🛠️ Tech Stack

### Backend Services
- **Java 17** - Core runtime
- **Spring Boot 3.3.x** - Application framework
- **Spring WebSocket** - Real-time communication
- **MyBatis Spring Boot Starter** - Database ORM
- **MySQL 8.0** - Primary database
- **Jackson** - JSON processing
- **JUnit 5** - Testing framework

### Security & Cryptography
- **RSA-4096** - Asymmetric encryption
- **RSASSA-PSS** - Digital signatures
- **Base64URL** - Safe encoding
- **SHA-256** - Hashing algorithms

### Client Applications
- **Python 3.x** - Client runtime
- **WebSocket** - Real-time communication
- **Cryptography** - Python crypto libraries

## 📁 Project Structure

```
SecureProgramming2/
├── introducer/                    # Central registry service
│   ├── src/main/java/edu/adelaide/
│   │   ├── IntroducerApplication.java
│   │   ├── server/                # WebSocket handlers
│   │   ├── service/               # Business logic
│   │   ├── util/                  # Utility classes
│   │   └── config/                # Configuration
│   └── src/main/resources/
│       ├── application.yml
│       └── config/keys/           # Cryptographic keys
├── server/                        # Distributed server nodes
│   ├── src/main/java/edu/adelaide/
│   │   ├── ServerApplication.java
│   │   ├── server/                # WebSocket handlers
│   │   ├── service/               # Business logic
│   │   ├── client/                # Client connections
│   │   ├── runtime/               # Background tasks
│   │   ├── util/                  # Utility classes
│   │   └── config/                # Configuration
│   └── src/main/resources/
│       ├── application.yml
│       ├── mappers/               # MyBatis XML mappers
│       └── config/keys/           # Cryptographic keys
├── client/                        # Python client applications
│   └── python/
│       ├── client.py              # Main client application
│       ├── file_transfer.py       # File transfer functionality
│       └── password_changer.py    # Password management
├── sql/                           # Database schemas
│   ├── week5/ddl/                 # User management tables
│   └── week9/ddl/                 # Group management tables
└── scripts/                       # Utility scripts
    ├── gen-keys.sh                # Key generation
    └── gen_user_keys_names_posix.sh
```

## 🚀 Quick Start

### Prerequisites

- **JDK 17** on `PATH`
- **Maven 3.9+**
- **MySQL 8.0** reachable at `localhost:3306`
- **Python 3.x** (for client applications)

### Database Setup

Create the database and required tables:

```sql
-- Create database
CREATE DATABASE secure_programming;

-- Create user management tables
SOURCE sql/week5/ddl/t_user_info.sql;

-- Create group management tables
SOURCE sql/week9/ddl/groups.sql;
SOURCE sql/week9/ddl/group_members.sql;
```

### Cryptographic Keys Setup

Generate RSA keys for the services:

```bash
# Generate introducer keys
cd introducer
./src/main/resources/scripts/dev-keygen.sh

# Generate server keys
cd ../server
./src/main/resources/scripts/dev-keygen.sh
```

### Database Configuration

_Connection used by the applications:_

- **Database**: `secure_programming`
- **User**: `secprog_migrate` (for generator/tests) / `secprog_app` (for runtime)
- **Password**: `1qaz!QAZ`

> You can change these in `application.yml` and `generatorConfig.xml` if needed.

## ⚙️ Configuration

### Server Configuration

`server/src/main/resources/application.yml`

```yaml
spring:
  datasource:
    url: jdbc:mysql://localhost:3306/secure_programming?allowPublicKeyRetrieval=true&useSSL=false&serverTimezone=Australia/Adelaide
    username: secprog_migrate
    password: 1qaz!QAZ
    driver-class-name: com.mysql.cj.jdbc.Driver

mybatis:
  mapper-locations: classpath:/mappers/*.xml
  type-aliases-package: edu.adelaide.entity

server:
  port: 8080

logging:
  level:
    edu.adelaide.mapper: debug
```

### Introducer Configuration

`introducer/src/main/resources/application.yml`

```yaml
server:
  port: 8100

introducer:
  registry: file:./data/server-registry.json
  private-key-location: classpath:config/keys/introducer_private.pem
```

## 🏃‍♂️ Running the Applications

### Start All Services

From the repository root:

```bash
# Clean & verify all modules
mvn -U clean verify

# Start introducer service (Terminal 1)
cd introducer
mvn spring-boot:run

# Start server application (Terminal 2)
cd ../server
mvn spring-boot:run
```

### Service Endpoints

- **Introducer Service**: <http://localhost:8100>
  - WebSocket: `ws://localhost:8100/ws` (Bootstrap registration only)
  - Registry: `./data/server-registry.json` (Server registry file)

- **Server Application**: <http://localhost:8080>
  - WebSocket: `ws://localhost:8080/ws` (Client communication + Inter-server)
  - REST API: <http://localhost:8080/api> (Admin operations)
  - Database: Direct MySQL connection (Port 3306)

### Python Client

```bash
# Install Python dependencies
cd client/python
pip install -r requirements.txt

# Run the client with parameters
python3 client.py --server ws://127.0.0.1:8080/ws --user-id alice
```

#### Client Parameters

- `--server` → WebSocket server URI
- `--user-id` → Username (e.g., alice, must match key files)

#### Example Usage

```bash
# Connect as user 'alice' to local server
python3 client/python/client.py --server ws://127.0.0.1:8080/ws --user-id alice

# Connect as user 'bob' to remote server
python3 client/python/client.py --server ws://192.168.1.100:8080/ws --user-id bob
```

#### Authentication

- Login with the password (default is USERNAME + '123', e.g., alice123)
- User key files must exist in the appropriate directory
- The system will prompt for password during login

## 🔧 Development Tools

### MyBatis Generator (MBG)

The project includes MyBatis Generator to create `entity`, `mapper` interfaces and XML based on your table(s).

- Config file: `server/src/main/resources/generatorConfig.xml`
- Maven plugin: `server/pom.xml`

#### Generate (manual)

```bash
cd server
# If you want a clean XML, delete the existing mapper first:
rm -f src/main/resources/mappers/UserInfoMapper.xml

# Run generator (single run; overwrite is enabled)
mvn org.mybatis.generator:mybatis-generator-maven-plugin:1.4.2:generate
```

> The generator is **not** bound to the build lifecycle by default to avoid accidental duplicate XML merges. Re-enable the `<executions>` block in `server/pom.xml` only if you want it to run automatically.

### Key Generation Scripts

```bash
# Generate server keys
cd server
./src/main/resources/scripts/dev-keygen.sh

# Generate introducer keys
cd ../introducer
./src/main/resources/scripts/dev-keygen.sh

# Generate user keys
cd ../scripts
./gen_user_keys_names_posix.sh
```

## 🧪 Testing

### Run All Tests

```bash
# Test server module
mvn -pl server test

# Test introducer module
mvn -pl introducer test

# Test all modules
mvn test
```

### Integration Tests

The project includes integration tests that:
1. Test user registration and authentication
2. Verify WebSocket communication
3. Test cryptographic operations
4. Validate database operations

### WebSocket Testing

Use the provided test client:

```bash
# Open in browser
open introducer/src/test/resources/ws-test.html
```

## 🔐 Security Features

### Cryptographic Security
- **RSA-4096 Encryption**: Secure message encryption between servers
- **RSASSA-PSS Signatures**: Message authentication and integrity
- **Base64URL Encoding**: Safe encoding for web transmission
- **SHA-256 Hashing**: Secure hash functions

### Authentication & Authorization
- **Server Authentication**: Mutual authentication between servers
- **User Authentication**: Secure user login and session management
- **Key Management**: Centralized key distribution and rotation

### Network Security
- **WebSocket Security**: Encrypted WebSocket connections
- **Peer Discovery**: Secure server discovery and registration
- **Message Integrity**: Cryptographic message verification

## 🚨 Troubleshooting

### Common Issues & Fixes

- **Mapper XML parsed twice / duplicate `BaseResultMap`:** ensure there is only one `UserInfoMapper.xml` under `resources/mappers`, and the generator's `isMergeable=false`. Delete the XML and regenerate if needed.
- **Public Key Retrieval is not allowed:** add `allowPublicKeyRetrieval=true&useSSL=false` to the JDBC URL (already present).
- **IDE shows red annotations but Maven build is green:** re‑import Maven, set JDK 17, enable Annotation Processing, and delete `.idea`/`*.iml` then re‑open the project.
- **WebSocket connection failed:** Check if both introducer and server are running on correct ports.
- **Key loading errors:** Ensure cryptographic keys are properly generated and placed in the correct directories.

### Log Files

- **Server logs**: `server/logs/server.log`
- **Introducer logs**: `introducer/logs/introducer.log`
- **Application logs**: `logs/` directory

## 📚 API Documentation

### WebSocket Endpoints

- **Introducer**: `ws://localhost:8100/ws`
  - Server registration and discovery (startup only)
  - Peer authentication and ID assignment

- **Server**: `ws://localhost:8080/ws`
  - Client communication (user messages, file transfer)
  - Inter-server messaging (peer-to-peer communication)
  - Heartbeat monitoring and presence updates

### REST API Endpoints

- **User Management**: `/api/users/*`
- **Group Management**: `/api/groups/*`
- **Admin Operations**: `/api/admin/*`

## 🧹 Git Hygiene

- IDE/project files are ignored via `.gitignore`:
  - `.idea/`, `*.iml`, build `target/`, `.DS_Store`
- If you accidentally added them, run:
  ```bash
  git rm -r --cached .idea *.iml target
  git commit -m "chore: stop tracking IDE/target files"
  ```

## 📈 Project Status

### ✅ Completed Features
- [x] **Server Module Refactoring**: Complete code optimization and refactoring
- [x] **Introducer Module Refactoring**: Full refactoring with utility consolidation
- [x] **Cryptographic Security**: RSA-4096 encryption and RSASSA-PSS signatures
- [x] **WebSocket Communication**: Real-time bidirectional messaging
- [x] **Database Integration**: MySQL with MyBatis ORM
- [x] **User Management**: Registration, authentication, and session management
- [x] **Group Management**: Multi-user group creation and management
- [x] **Python Client**: Complete client application with file transfer
- [x] **Code Optimization**: Removed unused methods and improved code quality
- [x] **Documentation**: Comprehensive README with setup instructions

### 🔄 Current Status
- **Server Module**: ✅ Fully functional and optimized
- **Introducer Module**: ✅ Fully functional and optimized
- **Client Applications**: ✅ Python clients ready for use
- **Database Schema**: ✅ Complete with user and group management
- **Security Implementation**: ✅ End-to-end encryption and authentication

### 🚀 Performance Improvements
- **Code Reduction**: Removed ~30% of redundant code through refactoring
- **Utility Consolidation**: Unified JSON, crypto, and message processing utilities
- **Base Classes**: Abstract base classes for handlers and services
- **Memory Optimization**: Reduced memory footprint through code consolidation

## 🤝 Contributing

### Development Guidelines
1. **Code Style**: Follow existing code patterns and Spring Boot conventions
2. **Security**: Always use the provided cryptographic utilities
3. **Testing**: Add tests for new features and bug fixes
4. **Documentation**: Update README for significant changes

### Pull Request Process
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Update documentation
6. Submit a pull request

## 👥 Team Members

- **a1887009** - Kurt Brice
- **a1886664** - Manith Kandanearachchi  
- **a1889846** - Tommy Pham
- **a1889461** - Patrick Chapman
- **a1915674** - William Qi

## 📄 License

Classroom/demo use.
