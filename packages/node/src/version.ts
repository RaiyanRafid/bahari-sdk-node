/** npm package name, sent in the X-Bahari-SDK header. */
export const PACKAGE = '@bahari/node';

/** Keep in sync with package.json. */
export const VERSION = '0.3.0';

/** The default X-Bahari-SDK header value, for example "@bahari/node/0.3.0". */
export const SDK = `${PACKAGE}/${VERSION}`;
