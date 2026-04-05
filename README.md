# Automated Log Analysis Using OpenAI and Elasticsearch

## Overview

This project analyzes security or system logs using AI and Elasticsearch. It allows you to clone the repository, install the required dependencies, and run the application locally.

---

# 1. Clone the Repository

Open a terminal and run:

```bash
git clone https://github.com/Keith11007/Automated-Log-Analysis-Using-OpenAI-and-Elasticsearch.git
```

This downloads the project files from GitHub into a new folder named:

```text
Automated-Log-Analysis-Using-OpenAI-and-Elasticsearch
```

---

# 2. Open the Project Folder

Move into the newly created project directory:

```bash
cd Automated-Log-Analysis-Using-OpenAI-and-Elasticsearch
```

---

# 3. Create a Virtual Environment

A virtual environment keeps this project's Python packages separate from the rest of your system.

On Linux (including Kali Linux):

```bash
python3 -m venv venv
```

This creates a folder called `venv` containing the isolated Python environment.

---

# 4. Activate the Virtual Environment

Because this project is being run on Kali Linux, use:

```bash
source venv/bin/activate
```

If successful, your terminal should change and look similar to:

```text
(venv) kali@kali:~/Automated-Log-Analysis-Using-OpenAI-and-Elasticsearch$
```

This means the virtual environment is active.

---

# 5. Install the Required Packages

Install all dependencies listed in `requirements.txt`:

```bash
pip install -r requirements.txt
```

What this does:

* Reads the `requirements.txt` file
* Downloads all required Python libraries
* Installs them into the virtual environment

Examples of packages that may be installed include:

* Flask
* OpenAI
* Elasticsearch
* Pandas
* Streamlit

---

# 6. Configure Environment Variables (If Needed)

Some projects require secret keys or configuration values, such as:

* OpenAI API key
* Elasticsearch URL
* Elasticsearch username/password

If the project includes a file such as:

```text
.env.example
```

Copy it to `.env`:

```bash
cp .env.example .env
```

Then edit the `.env` file and add your actual values.

Example:

```text
OPENAI_API_KEY=your_api_key_here
ELASTICSEARCH_URL=http://localhost:9200
```

---

# 7. Run the Project

Depending on how the application was built, use one of the following commands.

If the main file is `app.py`:

```bash
python app.py
```

If the project uses Streamlit:

```bash
streamlit run app.py
```

If the project uses Flask:

```bash
flask run
```

---

# 8. Open the Application in Your Browser

After running the project, your terminal may display a local address such as:

```text
http://127.0.0.1:5000
```

or

```text
http://localhost:8501
```

Open that address in your browser to use the application.

---

# 9. Stop the Project

To stop the application, return to the terminal and press:

```text
Ctrl + C
```

---

# 10. Deactivate the Virtual Environment

When you are finished, leave the virtual environment by running:

```bash
deactivate
```

---

# Troubleshooting

## "command not found" when activating the virtual environment

On Kali Linux or other Linux systems, do not use Windows commands such as:

```text
.\venv\Scripts\Activate.ps1
venv\Scripts\activate
```

Instead use:

```bash
source venv/bin/activate
```

## `pip install -r requirements.txt` fails

Try upgrading pip first:

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

## Python is not installed

Check whether Python is installed:

```bash
python3 --version
```

If not installed, install it with:

```bash
sudo apt update
sudo apt install python3 python3-venv python3-pip
```

---

# Full Setup Commands Together

```bash
git clone https://github.com/Keith11007/Automated-Log-Analysis-Using-OpenAI-and-Elasticsearch.git
cd Automated-Log-Analysis-Using-OpenAI-and-Elasticsearch
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```
