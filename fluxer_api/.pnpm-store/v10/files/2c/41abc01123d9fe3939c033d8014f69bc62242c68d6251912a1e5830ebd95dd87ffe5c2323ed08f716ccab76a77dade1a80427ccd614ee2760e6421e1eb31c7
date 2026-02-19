"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.utf8Len = exports.graphemeLen = void 0;
const utf8_grapheme_len_js_1 = require("./utf8-grapheme-len.js");
const utf8_len_js_1 = require("./utf8-len.js");
exports.graphemeLen = utf8_grapheme_len_js_1.graphemeLenNative ?? utf8_grapheme_len_js_1.graphemeLenPonyfill;
if (exports.graphemeLen === utf8_grapheme_len_js_1.graphemeLenPonyfill) {
    /*#__PURE__*/
    console.warn('[@atproto/lex-data]: Intl.Segmenter is not available in this environment. Falling back to ponyfill implementation.');
}
exports.utf8Len = utf8_len_js_1.utf8LenNode ?? utf8_len_js_1.utf8LenCompute;
//# sourceMappingURL=utf8.js.map