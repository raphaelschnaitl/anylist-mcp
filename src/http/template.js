import { readFileSync } from "fs";

const HTML_ESCAPES = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };

export function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, ch => HTML_ESCAPES[ch]);
}

/**
 * Express view engine for the simple HTML templates in ./views.
 * Section toggle: <!-- if:key -->...<!-- endif:key -->
 * Value replacement: {{key}} (HTML-escaped)
 */
export function renderTemplate(filePath, options, callback) {
  try {
    let content = readFileSync(filePath, "utf8");
    for (const [k, v] of Object.entries(options)) {
      // Truthy = boolean true, non-empty string, non-zero number
      const startTag = `<!-- if:${k} -->`;
      const endTag = `<!-- endif:${k} -->`;
      if (content.includes(startTag)) {
        const truthy = v !== null && v !== undefined && v !== false && v !== "" && v !== 0;
        if (!truthy) {
          const re = new RegExp(startTag + "[\\s\\S]*?" + endTag, "g");
          content = content.replace(re, "");
        } else {
          content = content.replaceAll(startTag, "").replaceAll(endTag, "");
        }
      }
      if (typeof v === "string" || typeof v === "number") {
        content = content.replaceAll(`{{${k}}}`, escapeHtml(v));
      } else if (v === null || v === undefined) {
        content = content.replaceAll(`{{${k}}}`, "");
      }
    }
    callback(null, content);
  } catch (err) {
    callback(err);
  }
}
