import {
  Alert,
  AlertVariant,
  Button,
  ClipboardCopyButton,
  Form,
  FormGroup,
  Modal,
  ModalBoxBody,
  ModalBoxFooter,
  PageSection,
  Spinner,
  Text,
  TextContent,
  TextInput,
  Title,
} from "@patternfly/react-core";
import { ExternalLinkAltIcon } from "@patternfly/react-icons";
import { useCallback, useEffect, useRef, useState } from "react";
import { Trans, useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import {
  AccountEnvironment,
  Page,
  useAccountAlerts,
  useEnvironment,
} from "@keycloak/keycloak-account-ui";
import {
  ChannelId,
  ChannelState,
  MfaChannels as MfaChannelsState,
  StartResult,
  fetchMfaChannels,
  pollTelegramScan,
  regenerateBackupCodes,
  removeChannel,
  startChannel,
  verifyChannel,
  verifyTelegram,
} from "../api/mfaChannels";
import { renderQr } from "../utils/qr";
import styles from "./MfaChannels.module.css";

/** How often the Telegram scan is re-read while the user is on their phone. */
const TELEGRAM_POLL_MS = 2000;

/** A channel being turned on, and whatever its first step handed back. */
type Pending = { channel: ChannelId; start: StartResult };

type Confirm = {
  channel: ChannelId;
  /** True when removing this leaves the user with no way to get a code at all. */
  stranded: boolean;
};

const CHANNEL_ORDER: ChannelId[] = ["telegram", "totp", "email", "backupCode"];

export const MfaChannels = () => {
  const { t } = useTranslation();
  const context = useEnvironment<AccountEnvironment>();
  const { addAlert, addError } = useAccountAlerts();

  const [state, setState] = useState<MfaChannelsState>();
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [pending, setPending] = useState<Pending>();
  const [confirm, setConfirm] = useState<Confirm>();
  const [codes, setCodes] = useState<string[]>();

  const reload = useCallback(
    (signal?: AbortSignal) => {
      fetchMfaChannels(context, signal)
        .then(setState)
        .catch((e) => {
          if (e instanceof DOMException && e.name === "AbortError") {
            return;
          }
          addError("mfaChannelsLoadError", e);
        })
        .finally(() => {
          if (!signal?.aborted) {
            setLoading(false);
          }
        });
    },
    [context, addError],
  );

  useEffect(() => {
    const controller = new AbortController();
    reload(controller.signal);
    return () => controller.abort();
  }, [reload]);

  const onRemove = useCallback(() => {
    if (!confirm) {
      return;
    }
    const target = confirm;
    setConfirm(undefined);
    setBusy(true);
    removeChannel(context, target.channel)
      .then((result) => {
        addAlert(
          result.willNeedEnrolment
            ? t("mfaRemoveNeedsEnrolment")
            : t("mfaRemoved", { channel: t(`mfaChannel.${target.channel}`) }),
          AlertVariant.success,
        );
        reload();
      })
      .catch((e) => addError("mfaRemoveError", e))
      .finally(() => setBusy(false));
  }, [confirm, context, addAlert, addError, reload, t]);

  const onAdd = useCallback(
    (channel: ChannelId) => {
      setBusy(true);
      startChannel(context, channel)
        .then((start) => setPending({ channel, start }))
        .catch((e) => addError("mfaAddError", { ...e, message: t(`mfaChannel.${channel}`) }))
        .finally(() => setBusy(false));
    },
    [context, addError, t],
  );

  const onRegenerate = useCallback(() => {
    setBusy(true);
    regenerateBackupCodes(context)
      .then((result) => {
        setCodes(result.codes);
        reload();
      })
      .catch((e) => addError("mfaRegenerateError", e))
      .finally(() => setBusy(false));
  }, [context, addError, reload]);

  if (loading) {
    return <Spinner />;
  }

  return (
    <Page title={t("signingIn")} description={t("signingInDescription")}>
      <PageSection className={styles.section}>
        <Title headingLevel="h2" size="xl">
          {t("mfaChannelsHeading")}
        </Title>

        {!state?.reachable && (
          <Alert
            variant="warning"
            isInline
            title={t("mfaChannelsUnreachable")}
            className={styles.callout}
          />
        )}

        <div className={styles.callout}>
          {/* Trans, not t(). The message bolds "every channel below", and <Trans> maps the tag in
              the message to a real element. A plain t() returns a string, which React escapes - so
              the markup reaches the page as visible text. i18n.ts setting escapeValue:false does not
              change that; it only governs how interpolated *variables* are escaped. */}
          <TextContent>
            <Text>
              <Trans
                i18nKey="mfaChannelsExplainer"
                components={{ strong: <strong /> }}
              />
            </Text>
          </TextContent>
        </div>

        {CHANNEL_ORDER.filter((c) => c === "backupCode" || state?.[c]?.active).map((channel) => (
          <ChannelCard
            key={channel}
            channel={channel}
            state={state![channel]}
            busy={busy}
            onReplace={() => onAdd(channel)}
            onRegenerate={onRegenerate}
            onRemove={() =>
              setConfirm({ channel, stranded: lastChannel(state!, channel) })
            }
          />
        ))}
      </PageSection>

      <PageSection className={styles.section}>
        <Title headingLevel="h2" size="xl">
          {t("mfaAddHeading")}
        </Title>

        {state && state.available.length === 0 ? (
          <div className={styles.emptyRow}>
            <div className={styles.emptyIcon}>
              <ShieldIcon />
            </div>
            <div className={styles.addText}>
              <div className={styles.addTitle}>{t("mfaAllChannelsSetUp")}</div>
              <div className={styles.addDetail}>{t("mfaNothingToAdd")}</div>
            </div>
          </div>
        ) : (
          state?.available.map((channel) => (
            <button
              key={channel}
              type="button"
              className={styles.addRow}
              disabled={busy || !state.reachable}
              onClick={() => onAdd(channel)}
              data-testid={`mfa-add-${channel}`}
            >
              <div className={styles.addIcon}>
                <ChannelIcon channel={channel} />
              </div>
              <div className={styles.addText}>
                <div className={styles.addTitle}>{t(`mfaChannel.${channel}`)}</div>
                <div className={styles.addDetail}>{t(`mfaChannelHint.${channel}`)}</div>
              </div>
            </button>
          ))
        )}
      </PageSection>

      {pending && (
        <SetupPanel
          pending={pending}
          context={context}
          onDone={() => {
            setPending(undefined);
            reload();
          }}
          onCancel={() => setPending(undefined)}
          onError={(e) => addError("mfaAddError", e)}
        />
      )}

      {codes && (
        <CodesPanel codes={codes} onClose={() => setCodes(undefined)} />
      )}

      <Modal
        isOpen={confirm !== undefined}
        variant="small"
        onClose={() => setConfirm(undefined)}
        title={t("mfaRemoveTitle", {
          channel: confirm ? t(`mfaChannel.${confirm.channel}`) : "",
        })}
      >
        <ModalBoxBody>
          {confirm?.stranded
            ? t("mfaRemoveLastChannelWarning")
            : t("mfaRemoveWarning", {
                channel: confirm ? t(`mfaChannel.${confirm.channel}`) : "",
              })}
        </ModalBoxBody>
        <ModalBoxFooter>
          <Button
            variant="danger"
            isDisabled={busy}
            data-testid="mfa-remove-confirm"
            onClick={onRemove}
          >
            {t("mfaRemoveConfirm")}
          </Button>
          <Button
            variant="link"
            onClick={() => setConfirm(undefined)}
            data-testid="mfa-remove-cancel"
          >
            {t("mfaRemoveCancel")}
          </Button>
        </ModalBoxFooter>
      </Modal>
    </Page>
  );
};

/**
 * Whether removing this channel would leave the user with nothing.
 *
 * <p>Derived from the live state rather than stored, because Telegram and Email ride one shared
 * privacyIDEA token: removing Email deletes that token, which is also the only thing the bot can send
 * a code through, so Telegram goes quiet as well. A page that counted channels would let somebody
 * turn off their last route home without being told.
 */
function lastChannel(state: MfaChannelsState, channel: ChannelId): boolean {
  if (channel === "email") {
    return !state.totp.active && !state.backupCode.active;
  }
  return !CHANNEL_ORDER.filter(
    (c) => c !== "backupCode" && c !== channel,
  ).some((c) => state[c].active);
}

const ChannelCard = ({
  channel,
  state,
  busy,
  onReplace,
  onRegenerate,
  onRemove,
}: {
  channel: ChannelId;
  state: ChannelState;
  busy: boolean;
  onReplace: () => void;
  onRegenerate: () => void;
  onRemove: () => void;
}) => {
  const { t } = useTranslation();

  return (
    <div className={styles.card} data-testid={`mfa-card-${channel}`}>
      <div className={styles.cardBody}>
        <div className={styles.cardText}>
          <div className={styles.cardTitle}>
            {t(`mfaChannel.${channel}`)}
            <span className={`${styles.pill} ${state.active ? "" : styles.pillOff}`}>
              {state.active ? t("mfaActive") : t("mfaInactive")}
            </span>
          </div>
          <div className={styles.cardDetail}>{describe(channel, state, t)}</div>
        </div>
      </div>

      <div className={styles.cardActions}>
        {channel === "telegram" && (
          <Button
            variant="secondary"
            isDisabled={busy}
            onClick={onReplace}
            data-testid="mfa-replace"
          >
            {t("mfaReplace")}
          </Button>
        )}
        {channel === "backupCode" ? (
          <Button
            variant="secondary"
            isDisabled={busy}
            onClick={onRegenerate}
            data-testid="mfa-regenerate"
          >
            {t("mfaGenerateMore")}
          </Button>
        ) : (
          <Button
            variant="link"
            isDanger
            isDisabled={busy}
            onClick={onRemove}
            data-testid="mfa-remove"
          >
            {t("mfaRemove")}
          </Button>
        )}
      </div>
    </div>
  );
};

/** The one line of detail under a channel's name. Parts are omitted rather than shown empty. */
function describe(channel: ChannelId, state: ChannelState, t: TFunction) {
  if (channel === "backupCode") {
    const parts = [
      state.count ? t("mfaCodesRemaining", { count: state.count }) : undefined,
      state.since ? t("mfaAdded", { date: formatSince(state.since) }) : undefined,
      t("mfaCodesEachOnce"),
      t("mfaCodesReplaceOnGenerate"),
    ];
    return parts.filter(Boolean).join(" · ");
  }

  if (channel === "telegram") {
    return [
      state.label ? t("mfaLinkedTo", { handle: state.label }) : undefined,
      state.since ? t("mfaAdded", { date: formatSince(state.since) }) : undefined,
    ]
      .filter(Boolean)
      .join(" · ");
  }

  if (channel === "email") {
    return [
      state.label ? t("mfaSentTo", { address: state.label }) : undefined,
      state.since ? t("mfaAdded", { date: formatSince(state.since) }) : undefined,
    ]
      .filter(Boolean)
      .join(" · ");
  }

  return [
    state.since ? t("mfaAdded", { date: formatSince(state.since) }) : undefined,
    t("mfaWorksOffline"),
  ]
    .filter(Boolean)
    .join(" · ");
}

function formatSince(value: string): string {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime())
    ? value
    : parsed.toLocaleDateString(undefined, { dateStyle: "long" });
}

/**
 * The second step of turning a channel on.
 *
 * <p>Authenticator app and email both finish by checking a typed code; Telegram finishes by watching
 * the bot for the scan, which needs no code at all. Mounted in a Modal so leaving it half-done
 * cannot leave the page claiming a channel is on when it is not.
 */
const SetupPanel = ({
  pending,
  context,
  onDone,
  onCancel,
  onError,
}: {
  pending: Pending;
  context: Parameters<typeof startChannel>[0];
  onDone: () => void;
  onCancel: () => void;
  onError: (e: unknown) => void;
}) => {
  const { t } = useTranslation();
  const { channel, start } = pending;
  const [code, setCode] = useState("");
const [submitting, setSubmitting] = useState(false);
const [error, setError] = useState<string>();
  // The library renders into the DOM, so the code is mounted here and the drawing happens in an
  // effect. A data-URL <img> was the previous approach; it could not carry a centre logo.
  const qrHost = useRef<HTMLDivElement>(null);

  const enrolmentUri = start.enrolmentUri;
  // The shared secret out of an otpauth:// URI. Kept as a variable because both the setup key and
  // the copy button need it, and re-deriving it inline twice is how a `undefined` reaches the DOM.
  const setupKey = enrolmentUri
    ? new URLSearchParams(enrolmentUri.split("?")[1] ?? "").get("secret") ?? ""
    : "";

  // Both channels that need a camera draw one: the authenticator app from its otpauth:// URI, and
  // Telegram from the deeplink that opens the bot. Sharing this effect is what stops the two from
  // drifting - the Telegram step shipped as a bare link with no QR at all precisely because it had
  // its own rendering path.
  const qrValue = enrolmentUri ?? (channel === "telegram" ? start.deepLink : undefined);

  // Depends on qrValue alone. `t` was in here before and that was the other half of the flicker: the
  // translator is not guaranteed a stable identity between renders, so an unrelated state change
  // re-ran this effect and redrew the code.
  useEffect(() => {
    const host = qrHost.current;
    if (!host || !qrValue) {
      return;
    }
    try {
      renderQr(host, qrValue, { telegram: channel === "telegram" });
    } catch (e) {
      // The authenticator app still has a usable secret below, so this is recoverable rather than
      // fatal - and an empty frame with no explanation is what shipped once before.
      console.error("Could not draw QR code", e);
      setError(t("mfaQrFailed"));
    }
    // `t` is read only on the failure path, which cannot re-run this effect; see above.
  }, [qrValue, channel]);


  // The poll reads the newest callbacks and messages through a ref so the effect below can depend on
  // nothing but the channel. It previously listed onDone, onError and t, none of which have a stable
  // identity - onDone is an inline arrow in the parent - so any re-render tore the loop down and
  // restarted it, restarting the two-second wait with it.
  const latest = useRef({ context, onDone, onError, t });
  latest.current = { context, onDone, onError, t };

  // Telegram: poll until the scan lands, then apply it. Closes the modal on success, because the
  // channel is then live and there is nothing left to do on this screen.
  useEffect(() => {
    if (channel !== "telegram") {
      return;
    }
    let cancelled = false;
    const poll = async () => {
      while (!cancelled) {
        await new Promise((resolve) => setTimeout(resolve, TELEGRAM_POLL_MS));
        if (cancelled) {
          return;
        }
        const { context: ctx, onDone: done, onError: fail, t: translate } = latest.current;
        try {
          await pollTelegramScan(ctx);
          // The server reports PENDING as 409 while the bot has not confirmed the scan. That is the
          // normal case and is not an error, so only a finished scan breaks the loop.
          await verifyTelegram(ctx);
          if (!cancelled) {
            done();
          }
          return;
        } catch (e) {
          const { status, code } = e as { status?: number; code?: string };
          // Only PENDING is worth retrying. Both it and a refusal arrive as 409, and treating them
          // alike meant a Telegram account that already belonged to someone else was retried until
          // the scan aged out, and then reported as an expired QR - which named neither the real
          // problem nor the account already holding it.
          if (status === 409 && code === "PENDING") {
            continue;
          }
          if (code === "ALREADY_LINKED") {
            setError(translate("mfaTelegramAlreadyLinked"));
            return;
          }
          if (status === 410 || status === 404) {
            // Show what the server said rather than assuming. These two used to be flattened into
            // one "that code expired" message, which told the user to start again when the real
            // fault was on this page and there was nothing to start again from.
            setError(status === 404
              ? t("mfaTelegramNoScan")
              : t("mfaTelegramExpired"));
            return;
          }
          fail(e);
          return;
        }
      }
    };
    void poll();
    return () => {
      cancelled = true;
    };
  }, [channel]);

  const submit = useCallback(() => {
    setSubmitting(true);
    setError(undefined);
    verifyChannel(context, channel, code)
      .then(onDone)
      .catch((e) =>
        setError(
          (e as { status?: number }).status === 401
            ? t("mfaCodeRejected")
            : t("mfaVerifyError"),
        ),
      )
      .finally(() => setSubmitting(false));
  }, [channel, code, context, onDone, t]);

  const digits = start.codeLength ?? 6;

  return (
    <Modal isOpen variant="medium" onClose={onCancel} title={t(`mfaChannel.${channel}`)}>
      <ModalBoxBody>
        {channel === "telegram" ? (
          <>
            <Text>{t("mfaTelegramScanPrompt", { bot: start.botUsername })}</Text>

            {/* The host is always mounted - the effect draws into it. Unmounting it to show a
                spinner first would mean the code appears a frame late, which reads as a flicker. */}
            <div
              ref={qrHost}
              className={styles.qr}
              role="img"
              aria-label={t("mfaTelegramQrAlt")}
              data-testid="mfa-telegram-qr"
            />

            {/* Two routes to the same place, because the QR is unusable on the machine you are
                sitting at: the link opens the bot on a phone, the copy button covers a desktop
                where the QR is off-screen or the phone camera cannot reach it. */}
            <div className={styles.deeplink}>
              <Button
                variant="primary"
                component="a"
                href={start.deepLink}
                target="_blank"
                rel="noopener noreferrer"
                icon={<ExternalLinkAltIcon />}
                data-testid="mfa-telegram-open"
              >
                {t("mfaOpenTelegram")}
              </Button>
            </div>

            {/* Copies from the element named by textId rather than a `value` prop, which is what
                PatternFly gives us here. Hidden from sight but kept in the DOM for textId to point
                at; showing the raw link as well as a QR is noise. */}
            <span id="mfa-telegram-deeplink-text" hidden>
              {start.deepLink}
            </span>
            <ClipboardCopyButton
              id="mfa-telegram-deeplink-copy"
              variant="plain"
              textId="mfa-telegram-deeplink-text"
              onClick={() => setCode("")}
            >
              {t("mfaCopyLinkInstead")}
            </ClipboardCopyButton>

            {/* No spinner or "waiting" line. The QR and the prompt above say what is happening, and
                a live countdown beside a code that may already have scanned says nothing. The poll
                closes this modal on its own the moment the link lands, so there is no state here that
                a waiting indicator could usefully report - it was only ever noise. */}
            {error && (
              <Alert variant="danger" isInline title={error} className={styles.formRow} />
            )}
          </>
        ) : (
          <>
            {channel === "totp" ? (
              <div
                ref={qrHost}
                className={styles.qr}
                role="img"
                aria-label={t("mfaTotpQrAlt")}
                data-testid="mfa-totp-qr"
              />
            ) : (
              <Alert
                variant="info"
                isInline
                title={t("mfaCodeSentTo", { address: start.label ?? "" })}
              />
            )}

            {/* The QR is a convenience, not the only route in: an authenticator app that cannot scan
                a screenshot still needs the secret, and the setup key below is the same value in
                typeable form. */}
            {enrolmentUri && (
              <div className={styles.formRow}>
                <div>
                  <TextContent>
                    <Text>{t("mfaSetupKey")}</Text>
                  </TextContent>
                  <code id="mfa-totp-secret-text" className={styles.setupKey}>
                    {setupKey}
                  </code>
                </div>
                <ClipboardCopyButton
                  id="mfa-totp-secret"
                  textId="mfa-totp-secret-text"
                  onClick={() => setCode("")}
                >
                  {t("mfaCopy")}
                </ClipboardCopyButton>
              </div>
            )}

            {error && (
              <Alert variant="danger" isInline title={error} className={styles.formRow} />
            )}

            <Form onSubmit={submit}>
              <FormGroup
                label={t("mfaEnterCode", { length: digits })}
                fieldId="mfa-setup-code"
              >
                {/* A plain text input rather than PatternFly's NumberInput, which is a quantity
                    stepper and has no notion of a fixed-length code. inputMode and the pattern
                    keep it to digits on a phone keyboard without a custom widget to maintain. */}
                <TextInput
                  id="mfa-setup-code"
                  value={code}
                  onChange={(_event, value) => setCode(value)}
                  type="text"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  maxLength={digits}
                  pattern="[0-9 ]*"
                  size={digits}
                  data-testid="mfa-setup-code"
                />
              </FormGroup>
              <Button
                variant="primary"
                type="submit"
                isDisabled={submitting || code.replace(/\s/g, "").length !== digits}
                data-testid="mfa-setup-submit"
              >
                {t("mfaConfirm")}
              </Button>
            </Form>
          </>
        )}
      </ModalBoxBody>
      <ModalBoxFooter>
        <Button variant="link" onClick={onCancel} data-testid="mfa-setup-cancel">
          {t("mfaCancel")}
        </Button>
      </ModalBoxFooter>
    </Modal>
  );
};

/** Shows a freshly issued set of backup codes. This is the only time they are ever readable. */
const CodesPanel = ({ codes, onClose }: { codes: string[]; onClose: () => void }) => {
  const { t } = useTranslation();
  const joined = codes.join("\n");
  const copied = useRef(false);

  return (
    <Modal isOpen variant="medium" onClose={onClose} title={t("mfaBackupCodesTitle")}>
      <ModalBoxBody>
        <Text>{t("mfaBackupCodesExplain")}</Text>
        <div className={styles.codes}>
          {codes.map((c) => (
            <code className={styles.code} key={c}>
              {c}
            </code>
          ))}
        </div>
        <Button
          variant="secondary"
          isDisabled={copied.current}
          onClick={() => {
            navigator.clipboard?.writeText(joined);
            copied.current = true;
          }}
        >
          {t("mfaCopyAll")}
        </Button>
      </ModalBoxBody>
      <ModalBoxFooter>
        <Button variant="primary" onClick={onClose} data-testid="mfa-codes-done">
          {t("mfaDone")}
        </Button>
      </ModalBoxFooter>
    </Modal>
  );
};

/** Inline SVG rather than an icon package: four shapes, and no new dependency for them. */
const ChannelIcon = ({ channel }: { channel: ChannelId }) => {
  const { t } = useTranslation();
  const label = t(`mfaChannel.${channel}`);
  if (channel === "telegram") {
    return (
      <svg width="20" height="20" viewBox="0 0 24 24" role="img" aria-label={label}>
        <path
          fill="currentColor"
          d="M21.9 4.3 18.7 19c-.2 1-.9 1.3-1.8.8l-4.9-3.6-2.4 2.3c-.3.3-.5.5-1 .5l.4-5 9.1-8.2c.4-.4-.1-.6-.6-.2L6.2 13.1 1.4 11.6c-1-.3-1-1 .2-1.5l19-7.3c.9-.3 1.6.2 1.3 1.5z"
        />
      </svg>
    );
  }
  if (channel === "totp") {
    return (
      <svg width="20" height="20" viewBox="0 0 24 24" role="img" aria-label={label}>
        <rect x="4" y="2" width="16" height="20" rx="2" fill="currentColor" />
        <rect x="7" y="5" width="10" height="9" fill="#fff" />
        <circle cx="12" cy="18" r="1.6" fill="#fff" />
      </svg>
    );
  }
  if (channel === "email") {
    return (
      <svg width="20" height="20" viewBox="0 0 24 24" role="img" aria-label={label}>
        <path
          fill="currentColor"
          d="M2 5h20v14H2zm2.6 2L12 12.6 19.4 7z"
        />
      </svg>
    );
  }
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" role="img" aria-label={label}>
      <path
        fill="currentColor"
        d="M12 1 3 5v6c0 5.6 3.8 10.7 9 12 5.2-1.3 9-6.4 9-12V5zm-1 15-4-4 1.4-1.4L11 13.2l5.6-5.6L18 9z"
      />
    </svg>
  );
};

/** Shown when every channel is already on, per the design's "All available channels are set up". */
const ShieldIcon = () => {
  const { t } = useTranslation();
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" role="img" aria-label={t("mfaAllChannelsSetUp")}>
      <path
        fill="currentColor"
        d="M12 1 3 5v6c0 5.6 3.8 10.7 9 12 5.2-1.3 9-6.4 9-12V5zm-1 15-4-4 1.4-1.4L11 13.2l5.6-5.6L18 9z"
      />
    </svg>
  );
};