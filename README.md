# Secure File Storage and Sharing System

A production-ready WSGI web application built with Python, Flask, and MySQL for managing physical file uploads, access permissions, and audit tracking.

## Features
- **User Authentication & RBAC:** Secure login with role-based access control (Admin vs. User).
- **File Management:** Physical disk storage handling using cross-platform absolute path resolution.
- **Granular Access Control:** File sharing protocols with database permission validation before streaming binaries.
- **Audit Logging:** System tracking for all user activities (uploads, downloads, shares, deletions).
- **WSGI Production Ready:** Configured with Waitress server for multi-device local network accessibility.

## Tech Stack
- **Backend:** Python, Flask, Waitress (WSGI Server)
- **Database:** MySQL
- **Frontend:** HTML5, CSS3, Jinja2 Templates

## Getting Started

### Prerequisites
- Python 3.x
- MySQL Server

### Installation & Setup
1. Clone the repository:
   ```bash
   git clone [https://github.com/yogita-shendkar/secure-file-storage.git](https://github.com/yogita-shendkar/secure-file-storage.git)
   cd secure-file-storage