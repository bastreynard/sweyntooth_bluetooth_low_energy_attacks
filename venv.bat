if exist venv (
    call venv/Scripts/activate
) else (
    echo "Creating virtual env..."
    python -m venv venv
    call venv/Scripts/activate
    pip install -r requirements.txt
)