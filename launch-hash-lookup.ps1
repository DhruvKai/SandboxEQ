# Change to the directory where the script is located
Set-Location -Path $PSScriptRoot

# Optional: Activate virtual environment here if you use one
# & "$PSScriptRoot\venv\Scripts\Activate.ps1"

# Run the FastAPI server with colors disabled
py -m uvicorn app:app --reload --no-use-colors

# Keep the window open to view output/errors
Pause
