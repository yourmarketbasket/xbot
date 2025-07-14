import requests

def test_use_default_credentials():
    url = "http://127.0.0.1:5000/api/use_default_credentials"
    headers = {"Content-Type": "application/json"}
    data = {"use_default": True}

    try:
        response = requests.post(url, json=data, headers=headers)
        response.raise_for_status()  # Raise an exception for bad status codes

        print("Response status code:", response.status_code)
        print("Response JSON:", response.json())

    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    test_use_default_credentials()
