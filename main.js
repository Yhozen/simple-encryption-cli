const aesjs = require('aes-js');
const pbkdf2 = require('pbkdf2');
const prompts = require('prompts');

const questions = [
    {
      type: 'password',
      name: 'password',
      message: 'Encryption password?'
    },
    {
      type: 'password',
      name: 'salt',
      message: 'Salt?'
    },
  ];

const menu = {
    type: 'select',
    name: 'option',
    message: 'Pick an option',
    choices: [
      { title: 'Encrypt data', description: 'Secure your data', value: 1 },
      { title: 'Decrypt data', description: 'Unlock your data', value: 2 },
      { title: 'Finish', description: 'Stop this program', value: 3 }
    ],
    initial: 0
  }

const encrypt = (aes, data) => {
    const dataBytes = aesjs.utils.utf8.toBytes(data)
    const encryptedBytes = aes.encrypt(dataBytes);
    return aesjs.utils.hex.fromBytes(encryptedBytes)
}

const decrypt = (aes, encryptedHex) => {
    const encryptedBytes = aesjs.utils.hex.toBytes(encryptedHex);
    const decryptedBytes = aes.decrypt(encryptedBytes)
    return aesjs.utils.utf8.fromBytes(decryptedBytes)
} 

const main = async () => {
    const {password, salt} = await prompts(questions);
    const key_256 = pbkdf2.pbkdf2Sync(password, salt, 1, 256 / 8, 'sha512');

    while (true) {
        const {option} = await prompts(menu);
        if (option == 3) break;
        if (option == 1) {
            const {data} = await prompts({
                type: 'text',
                name: 'data',
                message: 'Data to encrypt?'
            });
            const aesCtr = new aesjs.ModeOfOperation.ctr(key_256)

            const encrypted = encrypt(aesCtr,data)
            console.log(encrypted)
        } 
        if (option == 2) {
            const {data} = await prompts({
                type: 'text',
                name: 'data',
                message: 'Data to decrypt?'
            });
            const aesCtr = new aesjs.ModeOfOperation.ctr(key_256)

            const decrypted = decrypt(aesCtr, data)
            console.log(decrypted)
        } 

    }
}

main()

