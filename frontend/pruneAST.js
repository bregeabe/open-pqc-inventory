import { db } from "../db/client.js";

const CRYPTO_PATTERNS = {
  aes: ["\\baes\\b","aes-?\\d+","AESKey","AES\\.encrypt","AES\\.decrypt"],
  rsa: ["\\brsa\\b","rsa-?\\d+","RSAPublicKey","RSAPrivateKey","RSAKey"],
  signing: ["sign(ing)?","verify(ing)?","signature","digital[_ ]signature"],
  cert: ["certificate","x\\.509","public[_ ]?key","private[_ ]?key","pem","der"],
  hash: ["sha-?\\d+","hash","pbkdf2","scrypt","bcrypt","HMAC"],
  keys: ["api[_ ]?key","secret","token"]
};

const ALL_PATTERNS = new RegExp(
  Object.values(CRYPTO_PATTERNS).flat().join("|"),
  "i"
);

function pruneAstNode(node) {
  if (!node || typeof node !== "object") return null;

  let isMatch = false;
  const asString = JSON.stringify(node);
  if (ALL_PATTERNS.test(asString)) isMatch = true;

  const cloned = { ...node };

  for (const key in cloned) {
    if (Array.isArray(cloned[key])) {
      const prunedArray = cloned[key]
        .map(child => pruneAstNode(child))
        .filter(Boolean);

      if (prunedArray.length > 0) {
        cloned[key] = prunedArray;
        isMatch = true;
      } else {
        delete cloned[key];
      }
    } else if (typeof cloned[key] === "object" && cloned[key] !== null) {
      const prunedChild = pruneAstNode(cloned[key]);
      if (prunedChild) {
        cloned[key] = prunedChild;
        isMatch = true;
      } else {
        delete cloned[key];
      }
    }
  }

  return isMatch ? cloned : null;
}

function main() {
  console.log("Loading AST records from SQLite...");

  const rows = db.prepare(`
    SELECT astId, ast
    FROM fileAST
  `).all();

  let updated = 0;
  let skipped = 0;

  for (const row of rows) {
    try {
      const astJson = JSON.parse(row.ast);
      const pruned = pruneAstNode(astJson);

      if (!pruned) {
        skipped++;
        continue;
      }

      db.prepare(`
        UPDATE fileAST
        SET ast = ?
        WHERE astId = ?
      `).run(JSON.stringify(pruned), row.astId);

      updated++;

    } catch (err) {
      console.error("Failed to prune astId:", row.astId, err);
      skipped++;
    }
  }

  console.log(`\nPrune complete.`);
  console.log(`Updated ASTs: ${updated}`);
  console.log(`Skipped ASTs: ${skipped}`);
}

main();
