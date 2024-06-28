import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync,
} from "crypto";

const algorithm = `${process.env.CRYPTO_ALGORITHM}`;
const secretKey = scryptSync(`${process.env.CRYPTO_SECRET}`, "salt", 32); // Replace with your actual secret key
const ivLength = 16;

export function encrypt(text: string): string {
  console.log("it is", process.env);
  const iv = randomBytes(ivLength);
  const cipher = createCipheriv(algorithm, secretKey, iv);
  const encrypted = Buffer.concat([
    cipher.update(text, "utf8"),
    cipher.final(),
  ]);
  return `${iv.toString("hex")}:${encrypted.toString("hex")}`;
}

export function decrypt(text: string): string {
  const [ivHex, encryptedHex] = text.split(":");
  const iv = Buffer.from(ivHex, "hex");
  const encryptedText = Buffer.from(encryptedHex, "hex");
  const decipher = createDecipheriv(algorithm, secretKey, iv);
  const decrypted = Buffer.concat([
    decipher.update(encryptedText),
    decipher.final(),
  ]);
  return decrypted.toString("utf8");
}
