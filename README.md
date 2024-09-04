# 🔒 Secure File Encryptor/Decryptor

Safeguard your sensitive data with the **Secure File Encryptor/Decryptor**, a robust tool engineered for ultimate file protection. Whether you’re securing personal documents, confidential business files, or treasured memories, this application is designed to ensure your data remains private and inaccessible to unauthorized users.

![file encrypt](https://github.com/user-attachments/assets/98ce95cb-9eae-4838-9988-f49503dd1d4e)



## 🌟 Key Features

-   **Intuitive Interface**: Navigate the app with ease, thanks to a user-centric design that makes encrypting and decrypting your files and folders a breeze.
    
-   **Advanced Encryption**: Leverage powerful cryptography to secure individual files or entire directories, including all nested files and subfolders, offering flexible protection options.
    
-   **Password Protection**: Protect your files with a password. The app uses strong key derivation and encryption standards to ensure that only those with the correct password can access the encrypted data.
    
-   **Key Management**: Generate, save, and load encryption keys effortlessly. Control where and how your keys are stored, adding a personalized touch to your security setup.
    
-   **Process Transparency**: Receive real-time updates on encryption and decryption operations, keeping you informed every step of the way.
    

## 📁 Versions

### 1. Password-Based Encryption

**Description**: This version allows encryption and decryption using a password. It employs key derivation techniques to generate strong encryption keys from user-supplied passwords.

-   **File**: [password_encryption](./password_encryption.py)

### 2. Key-Based Encryption

**Description**: This version offers encryption using a secret key. Users can generate, save, and load secret keys, which are then used for encryption and decryption.

-   **File**: [key_encryption](./key_encryption.py)

## 🚀 Getting Started

Follow these steps to set up and run the application:

1.  **Clone the repository**:
    
   
    
    `git clone https://github.com/swissmarley/file-encryptor.git
    cd file-encryptor` 
    
2.  **Install required packages**:
    
    
    
    `pip install -r requirements.txt` 
    
3.  **Run the Application**:
    
    -   For password-based encryption:
        
       
        
        `python password_encryption.py` 
        
    -   For key-based encryption:
        
      
        
        `python key_encryption.py` 
        

## 📄 License

This project is licensed under the MIT License. For more details, refer to the [LICENSE](LICENSE) file.
