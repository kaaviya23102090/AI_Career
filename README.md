#  AI Career — AI-Powered Career Guidance Platform

> A Flask-based career guidance web application that delivers personalized college recommendations and AI-driven mentorship using Groq's Llama 3.3 model.

---

## overview

**AI Career** is an intelligent career counseling platform designed to help students navigate their academic and professional journey. By leveraging the power of large language models, it provides personalized college recommendations, career path suggestions, and real-time AI mentorship — all through a clean, conversational chat interface.

---

## Features

-  **AI-Powered Chatbot** — Conversational career guidance powered by Groq's Llama 3.3 model
-  **Personalized College Recommendations** — Tailored suggestions based on user inputs and preferences
-  **Secure User Authentication** — Login and registration system built with Flask-Login
-  **Persistent Chat History** — All conversations stored and retrieved via SQLite database
-  **Web Deployment** — Hosted on OneCompiler with Cloudflare for secure DNS and environment management

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python, Flask, Flask-Login |
| AI Model | Groq API — Llama 3.3 |
| Database | SQLite |
| Frontend | HTML, CSS, JavaScript |
| Hosting | OneCompiler |
| DNS & Security | Cloudflare |

---

## 📁 Project Structure

```
AI_Career/
│
├── app.py              # Main Flask application — routes, auth, chat logic
├── index.html          # Landing / Home page
├── frontend.html       # Main frontend UI
├── frontend1.html      # Alternate frontend page
├── auth3.html          # User authentication page (login/register)
├── chatbot3.html       # Chatbot interface
├── exce_code.gs        # Google Apps Script for Excel/Sheets integration
├── PROJ DB.xlsx        # Project database / data reference
├── notes.txt           # Developer notes
└── README.md           # Project documentation
```

---

## Getting Started

### Prerequisites

Make sure you have the following installed:

- Python 3.8+
- pip

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/kaaviya23102090/AI_Career.git
   cd AI_Career
   ```

2. **Install dependencies**
   ```bash
   pip install flask flask-login groq
   ```

3. **Set up your Groq API key**

   Create a `.env` file in the root directory:
   ```
   GROQ_API_KEY=your_groq_api_key_here
   ```

4. **Run the application**
   ```bash
   python app.py
   ```

5. **Open in browser**
   ```
   http://localhost:5000
   ```

---

##  Environment Variables

| Variable | Description |
|---|---|
| `GROQ_API_KEY` | Your Groq API key for Llama 3.3 model access |
| `SECRET_KEY` | Flask secret key for session management |

---

##  How It Works

1. User registers or logs in through the authentication page
2. User enters career-related queries in the chatbot interface
3. The query is sent to the Groq Llama 3.3 model via API
4. The AI responds with personalized college recommendations and career advice
5. The conversation is saved to the SQLite database for future reference

---

##  Deployment

The application is deployed using:
- **OneCompiler** — for application hosting
- **Cloudflare** — for secure DNS management and environment variable protection

---

