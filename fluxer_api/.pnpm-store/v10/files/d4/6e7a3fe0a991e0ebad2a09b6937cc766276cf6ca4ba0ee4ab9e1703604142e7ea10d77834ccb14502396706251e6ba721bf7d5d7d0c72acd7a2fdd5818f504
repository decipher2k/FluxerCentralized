"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.fromBase64 = exports.toBase64 = void 0;
exports.asUint8Array = asUint8Array;
exports.ui8Equals = ui8Equals;
const uint8array_from_base64_js_1 = require("./uint8array-from-base64.js");
const uint8array_to_base64_js_1 = require("./uint8array-to-base64.js");
// @TODO drop dependency on uint8arrays package once Uint8Array.fromBase64 /
// Uint8Array.prototype.toBase64 is widely supported, and mark fromBase64 /
// toBase64 as deprecated. We can also drop NodeJS specific implementations
// once NodeJS <24 is no longer supported.
/**
 * Encodes a Uint8Array into a base64 string.
 *
 * @returns The base64 encoded string
 */
exports.toBase64 = uint8array_to_base64_js_1.toBase64Native ?? uint8array_to_base64_js_1.toBase64Node ?? uint8array_to_base64_js_1.toBase64Ponyfill;
/**
 * Decodes a base64 string into a Uint8Array. This function supports both padded
 * and unpadded base64 strings.
 *
 * @returns The decoded {@link Uint8Array}
 * @throws If the input is not a valid base64 string
 */
exports.fromBase64 = uint8array_from_base64_js_1.fromBase64Native ?? uint8array_from_base64_js_1.fromBase64Node ?? uint8array_from_base64_js_1.fromBase64Ponyfill;
if (exports.toBase64 === uint8array_to_base64_js_1.toBase64Ponyfill || exports.fromBase64 === uint8array_from_base64_js_1.fromBase64Ponyfill) {
    /*#__PURE__*/
    console.warn('[@atproto/lex-data]: Uint8Array.fromBase64 / Uint8Array.prototype.toBase64 not available in this environment. Falling back to ponyfill implementation.');
}
/**
 * Coerces various binary data representations into a Uint8Array.
 *
 * @return `undefined` if the input could not be coerced into a {@link Uint8Array}.
 */
function asUint8Array(input) {
    if (input instanceof Uint8Array) {
        return input;
    }
    if (ArrayBuffer.isView(input)) {
        return new Uint8Array(input.buffer, input.byteOffset, input.byteLength / Uint8Array.BYTES_PER_ELEMENT);
    }
    if (input instanceof ArrayBuffer) {
        return new Uint8Array(input);
    }
    return undefined;
}
function ui8Equals(a, b) {
    if (a.byteLength !== b.byteLength) {
        return false;
    }
    for (let i = 0; i < a.byteLength; i++) {
        if (a[i] !== b[i]) {
            return false;
        }
    }
    return true;
}
//# sourceMappingURL=uint8array.js.map