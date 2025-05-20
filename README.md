# Secure QR Code Attendance System

A Django-based attendance system that uses one-time QR codes with advanced security features.

## Features

- 🔐 Login Required: Only authenticated users can scan and register attendance
- 🔄 One-Time Use QR Codes: Each QR code is valid for a single use
- 🌐 IP Address Tracking: Captures and validates user IP addresses
- 🛡️ VPN/Proxy Detection: Blocks requests from VPNs, proxies, and VPSs
- 🤖 Bot Protection: Implements rate limiting and User-Agent validation
- 🔄 Real-Time Updates: QR codes automatically refresh after use

## Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Virtual environment (recommended)

## Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd AVC_ATT
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Set up environment variables:
   Create a `.env` file in the project root with the following variables:
   ```
   DEBUG=False
   SECRET_KEY=your-secret-key
   SITE_URL=https://your-domain.com
   ```

5. Run migrations:
   ```bash
   python manage.py makemigrations
   python manage.py migrate
   ```

6. Create a superuser:
   ```bash
   python manage.py createsuperuser
   ```

7. Run the development server:
   ```bash
   python manage.py runserver
   ```

## Production Deployment

1. Update `settings.py`:
   - Set `DEBUG = False`
   - Configure your domain in `SITE_URL`
   - Set up proper database (e.g., PostgreSQL)
   - Configure static files with WhiteNoise

2. Collect static files:
   ```bash
   python manage.py collectstatic
   ```

3. Use Gunicorn as the WSGI server:
   ```bash
   gunicorn AVC_ATT.wsgi:application
   ```

## Security Features

- SSL/TLS encryption (HTTPS required)
- CSRF protection
- XSS filtering
- Rate limiting
- IP intelligence checks
- User-Agent validation
- One-time use tokens
- Session security

## Usage

1. Log in to the system using your credentials
2. Access the dashboard to view the current QR code
3. Users can scan the QR code to mark attendance
4. The system automatically generates a new QR code after each use
5. View attendance history in the history section

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support, please open an issue in the repository or contact the maintainers. 