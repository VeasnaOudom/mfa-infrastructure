/**
 * QR rendering for the account console.
 *
 * <p>Deliberately the same library, at the same version, as the login theme's enrolment screens -
 * `themes/khalibre/login/resources/js/qr-code-styling-1.9.2.js`, vendored into
 * `src/vendor-qrcode-styling.cjs`. A user who scans a code on one screen and then meets the other
 * should not be looking at two different-looking codes, and matching the options here is what
 * guarantees that. See the `new QRCodeStyling({...})` calls in `edc-enrol.js` for the reference.
 *
 * <p>The Telegram logo at 40% of the code is the login theme's `imageSize`, and it is not a taste
 * decision: a smaller icon needs a plate knocked out of the modules underneath it, which is what
 * made an earlier attempt here look like a blob. This library composites the image with the error
 * correction level chosen for the job, so the code still scans.
 */
import { environment } from "../environment";
import QRCodeStyling from "../vendor-qrcode-styling.cjs";

/**
 * Where the vendored Telegram mark is served from.
 *
 * <p>Built from the theme's own `resourceUrl` rather than a relative path. The account page sets
 * `<base href="${resourceUrl}/">`, so a relative URL would usually resolve correctly - but the
 * library loads the image with its own fetch, and in dev mode the document is still served from
 * Keycloak while the bundle comes from Vite, so relative resolution is ambiguous exactly when it is
 * hardest to debug. `resourceUrl` is the same value the page's own assets use.
 */
const TELEGRAM_LOGO = `${environment.resourceUrl.replace(/\/$/, "")}/img/telegram.svg`;

type QrOptions = {
  /** Rendered size in CSS pixels. */
  size?: number;
  /** Draw the Telegram mark in the centre. */
  telegram?: boolean;
};

/**
 * Replaces the contents of `host` with a QR code for `data`.
 *
 * <p>Appends rather than returning markup, because that is the library's API. Called on every
 * `data` change; a code whose value has not changed is left alone, so a poll tick cannot redraw the
 * thing the user is trying to point a camera at.
 */
export function renderQr(host: HTMLElement, data: string, options: QrOptions = {}): void {
  const size = options.size ?? 208;
  const existing = host.dataset.qrFor;
  if (existing === data && host.firstChild) {
    return;
  }
  host.replaceChildren();
  host.dataset.qrFor = data;

  const code = new QRCodeStyling({
    width: size,
    height: size,
    type: "svg",
    data,
    // Rounded dots and extra-rounded corners, to match the enrolment screens.
    dotsOptions: { color: "#000000", type: "rounded" },
    cornersSquareOptions: { type: "extra-rounded" },
    backgroundOptions: { color: "#ffffff" },
    ...(options.telegram
      ? {
          image: TELEGRAM_LOGO,
          imageOptions: { saveAsBlob: true, imageSize: 0.4, margin: 0 },
          // H-grade correction is what buys enough redundancy for a 40% logo to still scan. The
          // login theme uses M here; that is a deliberate difference, because its logo is drawn at
          // the same size but this screen has no fallback to retype a secret from.
          qrOptions: { errorCorrectionLevel: "H" },
        }
      : { qrOptions: { errorCorrectionLevel: "M" } }),
  });

  code.append(host);
}

/** Empties a host, so a stale code is not left on screen behind a spinner. */
export function clearQr(host: HTMLElement): void {
  host.replaceChildren();
  delete host.dataset.qrFor;
}
