/**
 * Types for the vendored copy of qr-code-styling 1.9.2, which ships as an untyped UMD bundle.
 *
 * Only the options this project passes are declared. If the real signature turns out to be narrower,
 * TypeScript will not catch it here - see the comment on errorCorrectionLevel in utils/qr.ts.
 */
type QrCodeStylingOptions = {
  width?: number;
  height?: number;
  type?: "canvas" | "svg";
  data?: string;
  image?: string;
  margin?: number;
  dotsOptions?: { color?: string; type?: string };
  cornersSquareOptions?: { type?: string };
  backgroundOptions?: { color?: string };
  imageOptions?: { hideBackgroundDots?: boolean; imageSize?: number; margin?: number; crossOrigin?: string; saveAsBlob?: boolean };
  qrOptions?: { typeNumber?: number; mode?: string; errorCorrectionLevel?: "L" | "M" | "Q" | "H" };
};

declare class QRCodeStyling {
  constructor(options?: QrCodeStylingOptions);
  append(container: HTMLElement | string): QRCodeStyling;
  update(options: Partial<QrCodeStylingOptions>): QRCodeStyling;
}

export default QRCodeStyling;
