/**
 * Translations: English, Farsi, Dutch.
 *
 * Rules:
 *  - Farsi is RTL; the shell flips `dir` when the locale is `fa`.
 *  - Every user-visible string lives here. Nothing is hardcoded in the UI, so a
 *    missing translation is a build error rather than a silent English leak.
 *  - Parameters use `{name}` placeholders and are substituted with textContent
 *    only (never innerHTML), so a message containing markup cannot inject.
 */

export type Locale = 'en' | 'fa' | 'nl';

export const LOCALES: readonly Locale[] = ['en', 'fa', 'nl'];

export const LOCALE_NAMES: Record<Locale, string> = {
  en: 'English',
  fa: 'فارسی',
  nl: 'Nederlands',
};

export const RTL_LOCALES: ReadonlySet<Locale> = new Set<Locale>(['fa']);

type Dict = Record<string, string>;

const en: Dict = {
  'app.name': 'YSM',
  'app.tagline': 'Youtab Security Message',

  'nav.chats': 'Chats',
  'nav.crypto': 'Crypto',
  'nav.contacts': 'Contacts',
  'nav.settings': 'Settings',

  'crypto.writeTab': 'Encrypt',
  'crypto.readTab': 'Decrypt',
  'crypto.messageLabel': 'Message',
  'crypto.messagePlaceholder': 'Type the message you want to encrypt…',
  'crypto.pickFile': 'Choose a file',
  'crypto.writeHint': 'You will get two things: a reference (YSM_…) and a passphrase. Send them through different channels.',
  'crypto.create': 'Create crypto',
  'crypto.resultTitle': 'Ready — two things to send',
  'crypto.resultHint': 'Give both to the reader. Without the passphrase nobody can open it, including you.',
  'crypto.referenceLabel': 'Reference',
  'crypto.referencePlaceholder': 'YSM_… (64 hex characters)',
  'crypto.passphraseLabel': 'Passphrase',
  'crypto.passphraseWarning': 'The passphrase is not stored anywhere. If you lose it, this message can never be read again.',
  'crypto.saveBlock': 'Download block',
  'crypto.startOver': 'Start over',
  'crypto.readHint': 'Paste the reference, type the passphrase, and open.',
  'crypto.open': 'Decrypt',
  'crypto.openedTitle': 'Decrypted',
  'crypto.download': 'Download file',

  'common.cancel': 'Cancel',
  'common.save': 'Save',
  'common.close': 'Close',
  'common.copy': 'Copy',
  'common.copied': 'Copied',
  'common.back': 'Back',
  'common.next': 'Next',
  'common.done': 'Done',
  'common.delete': 'Delete',
  'common.confirm': 'Confirm',
  'common.loading': 'Loading…',
  'common.optional': 'optional',
  'common.required': 'required',
  'common.retry': 'Try again',

  'boot.title': 'Welcome to YSM',
  'boot.subtitle': 'End-to-end encrypted messages that never leave your device unencrypted.',
  'boot.create': 'Create a new account',
  'boot.unlock': 'Unlock existing account',

  'create.title': 'Create your account',
  'create.displayName': 'Display name',
  'create.displayNameHint': 'Shown to people you talk to. You can change it later.',
  'create.password': 'Password',
  'create.passwordHint': 'At least 12 characters. This password encrypts everything on this device.',
  'create.passwordConfirm': 'Confirm password',
  'create.mismatch': 'Passwords do not match.',
  'create.submit': 'Create account',
  'create.working': 'Deriving keys…',
  'create.weak': 'This password is too weak.',

  'onboard.title': 'Set up two-factor authentication',
  'onboard.intro':
    'YSM requires an authenticator code every time you unlock. Scan this with Google Authenticator, Authy, or any TOTP app.',
  'onboard.secretLabel': 'Or enter this key manually',
  'onboard.verifyLabel': 'Enter the 6-digit code from your app',
  'onboard.verify': 'Verify and finish',
  'onboard.recoveryTitle': 'Save your recovery codes',
  'onboard.recoveryIntro':
    'If you lose your authenticator app, these are the only way back in. Each code works once. Store them somewhere safe and offline.',
  'onboard.recoveryAck': 'I have saved my recovery codes',
  'onboard.copiedAll': 'Copy all codes',
  'onboard.downloadPdf': 'Download PDF',
  'onboard.downloadCsv': 'Download CSV',

  'unlock.title': 'Unlock YSM',
  'unlock.password': 'Password',
  'unlock.code': 'Authenticator code',
  'unlock.submit': 'Unlock',
  'unlock.working': 'Unlocking…',
  'unlock.badPassword': 'Incorrect password.',
  'unlock.badTotp': 'Incorrect authenticator code.',
  'unlock.replay': 'That code was already used. Wait for the next one.',
  'unlock.lockedOut': 'Too many attempts. Try again in {seconds}s.',
  'unlock.useRecovery': 'Use a recovery code instead',
  'unlock.recoveryLabel': 'Recovery code',

  'chats.empty': 'No conversations yet',
  'chats.emptyHint': 'Add a contact to start an encrypted conversation.',
  'chats.newChat': 'New chat',
  'chats.composerPlaceholder': 'Write a message…',
  'chats.send': 'Send',
  'chats.attach': 'Attach a file',
  'chats.verified': 'Verified',
  'chats.unverified': 'Not verified',
  'chats.noMessages': 'No messages yet. Say hello.',
  'chats.encrypted': 'End-to-end encrypted',
  'chats.sendEnvelope': 'Export encrypted file',
  'chats.importEnvelope': 'Import encrypted file',

  'contacts.title': 'Contacts',
  'contacts.add': 'Add contact',
  'contacts.empty': 'No contacts yet.',
  'contacts.paste': 'Paste your contact’s card',
  'contacts.pasteHint': 'Ask them for their YSM contact card and paste it here.',
  'contacts.addSubmit': 'Add contact',
  'contacts.invalid': 'That is not a valid YSM contact card.',
  'contacts.badSignature': 'The card’s signature is invalid — it may have been tampered with.',
  'contacts.myCard': 'My contact card',
  'contacts.myCardHint': 'Share this with someone so they can add you.',
  'contacts.safetyTitle': 'Safety number',
  'contacts.safetyIntro':
    'Compare these numbers with {name} in person or over a call. If they match, no one is intercepting your messages.',
  'contacts.markVerified': 'Numbers match — mark as verified',
  'contacts.verifiedBadge': 'Verified',
  'contacts.remove': 'Remove contact',

  'file.selected': 'Attached: {name}',
  'file.tooBig': 'This file is too large (limit {limit}).',
  'file.sending': 'Encrypting {name}…',
  'file.save': 'Save',
  'file.saved': 'Saved',
  'file.blocked': 'This file type cannot be opened from inside YSM for safety.',

  'settings.title': 'Settings',
  'settings.language': 'Language',
  'settings.account': 'Account',
  'settings.displayName': 'Display name',
  'settings.security': 'Security',
  'settings.lockNow': 'Lock now',
  'settings.lockWarning': 'Locking clears all keys from memory. You will need your password and authenticator to unlock again.',
  'settings.about': 'About',
  'settings.version': 'Version {version}',
  'settings.privacy': 'Privacy',
  'settings.privacyText':
    'YSM has no telemetry, no analytics and no servers. Nothing you do in this app is ever sent anywhere. Messages only leave your device as encrypted files that you export yourself.',
  'settings.noTelemetry': 'No telemetry. No servers. No tracking.',
  'settings.autoLock': 'Auto-lock after',
  'settings.autoLockSaved': 'Auto-lock updated',
  'settings.autoLockOff': 'Never',
  'settings.minutes': '{n} minutes',

  'error.generic': 'Something went wrong.',
  'error.locked': 'The vault is locked.',
  'error.importFailed': 'This file could not be imported: {reason}',
  'error.badEnvelope': 'This is not a valid YSM encrypted file.',
  'error.keyMismatch': 'The sender’s key does not match the saved contact.',
  'error.unknownSender': 'Message from an unknown sender.',

  'toast.messageSent': 'Message encrypted',
  'toast.fileImported': 'File imported and decrypted',
  'toast.contactAdded': 'Contact added',
  'toast.contactVerified': 'Contact marked as verified',
};

const fa: Dict = {
  'app.name': 'YSM',
  'app.tagline': 'پیام امن یوتاب',

  'nav.chats': 'گفتگوها',
  'nav.crypto': 'رمزنگاری',
  'nav.contacts': 'مخاطبین',
  'nav.settings': 'تنظیمات',

  'crypto.writeTab': 'رمزگذاری',
  'crypto.readTab': 'رمزگشایی',
  'crypto.messageLabel': 'متن پیام',
  'crypto.messagePlaceholder': 'متنی که می‌خواهید رمز شود را بنویسید…',
  'crypto.pickFile': 'انتخاب فایل',
  'crypto.writeHint': 'دو چیز می‌گیرید: یک مرجع (YSM_…) و یک رمز. آن‌ها را از دو مسیر جدا بفرستید.',
  'crypto.create': 'ساخت رمز',
  'crypto.resultTitle': 'آماده است — دو چیز برای ارسال',
  'crypto.resultHint': 'هر دو را به خواننده بدهید. بدون رمز، هیچ‌کس نمی‌تواند باز کند — حتی خودتان.',
  'crypto.referenceLabel': 'مرجع',
  'crypto.referencePlaceholder': 'YSM_… (۶۴ کاراکتر)',
  'crypto.passphraseLabel': 'رمز',
  'crypto.passphraseWarning': 'رمز هیچ‌جا ذخیره نمی‌شود. اگر گمش کنید، این پیام هرگز خوانده نمی‌شود.',
  'crypto.saveBlock': 'دانلود بلوک',
  'crypto.startOver': 'از نو',
  'crypto.readHint': 'مرجع را بچسبانید، رمز را بنویسید و باز کنید.',
  'crypto.open': 'رمزگشایی',
  'crypto.openedTitle': 'رمزگشایی شد',
  'crypto.download': 'دانلود فایل',

  'common.cancel': 'انصراف',
  'common.save': 'ذخیره',
  'common.close': 'بستن',
  'common.copy': 'کپی',
  'common.copied': 'کپی شد',
  'common.back': 'بازگشت',
  'common.next': 'بعدی',
  'common.done': 'تمام',
  'common.delete': 'حذف',
  'common.confirm': 'تأیید',
  'common.loading': 'در حال بارگذاری…',
  'common.optional': 'اختیاری',
  'common.required': 'الزامی',
  'common.retry': 'تلاش دوباره',

  'boot.title': 'به YSM خوش آمدید',
  'boot.subtitle': 'پیام‌های رمزنگاری‌شده سرتاسری که هرگز بدون رمز از دستگاه شما خارج نمی‌شوند.',
  'boot.create': 'ساخت حساب جدید',
  'boot.unlock': 'باز کردن حساب موجود',

  'create.title': 'ساخت حساب کاربری',
  'create.displayName': 'نام نمایشی',
  'create.displayNameHint': 'این نام به مخاطبین شما نشان داده می‌شود.',
  'create.password': 'گذرواژه',
  'create.passwordHint': 'حداقل ۱۲ کاراکتر. این گذرواژه همه‌چیز روی این دستگاه را رمز می‌کند.',
  'create.passwordConfirm': 'تکرار گذرواژه',
  'create.mismatch': 'گذرواژه‌ها یکسان نیستند.',
  'create.submit': 'ساخت حساب',
  'create.working': 'در حال تولید کلیدها…',
  'create.weak': 'این گذرواژه بیش از حد ضعیف است.',

  'onboard.title': 'راه‌اندازی تأیید دو مرحله‌ای',
  'onboard.intro':
    'YSM هر بار که حساب را باز می‌کنید یک کد از برنامه احراز هویت می‌خواهد. این کد را با Google Authenticator یا هر برنامه TOTP اسکن کنید.',
  'onboard.secretLabel': 'یا این کلید را دستی وارد کنید',
  'onboard.verifyLabel': 'کد ۶ رقمی برنامه را وارد کنید',
  'onboard.verify': 'تأیید و پایان',
  'onboard.recoveryTitle': 'کدهای بازیابی را ذخیره کنید',
  'onboard.recoveryIntro':
    'اگر برنامه احراز هویت را از دست بدهید، این کدها تنها راه بازگشت شما هستند. هر کد فقط یک بار کار می‌کند. آن‌ها را در جای امن و آفلاین نگه دارید.',
  'onboard.recoveryAck': 'کدهای بازیابی را ذخیره کردم',
  'onboard.copiedAll': 'کپی همه کدها',
  'onboard.downloadPdf': 'دانلود PDF',
  'onboard.downloadCsv': 'دانلود CSV',

  'unlock.title': 'باز کردن YSM',
  'unlock.password': 'گذرواژه',
  'unlock.code': 'کد احراز هویت',
  'unlock.submit': 'باز کن',
  'unlock.working': 'در حال باز کردن…',
  'unlock.badPassword': 'گذرواژه نادرست است.',
  'unlock.badTotp': 'کد احراز هویت نادرست است.',
  'unlock.replay': 'این کد قبلاً استفاده شده است. منتظر کد بعدی بمانید.',
  'unlock.lockedOut': 'تلاش‌های بیش از حد. {seconds} ثانیه دیگر دوباره تلاش کنید.',
  'unlock.useRecovery': 'استفاده از کد بازیابی',
  'unlock.recoveryLabel': 'کد بازیابی',

  'chats.empty': 'هنوز گفتگویی ندارید',
  'chats.emptyHint': 'برای شروع یک گفتگوی رمزنگاری‌شده یک مخاطب اضافه کنید.',
  'chats.newChat': 'گفتگوی جدید',
  'chats.composerPlaceholder': 'پیام بنویسید…',
  'chats.send': 'ارسال',
  'chats.attach': 'پیوست فایل',
  'chats.verified': 'تأییدشده',
  'chats.unverified': 'تأییدنشده',
  'chats.noMessages': 'هنوز پیامی نیست. سلام کنید.',
  'chats.encrypted': 'رمزنگاری سرتاسری',
  'chats.sendEnvelope': 'خروجی فایل رمزشده',
  'chats.importEnvelope': 'ورود فایل رمزشده',

  'contacts.title': 'مخاطبین',
  'contacts.add': 'افزودن مخاطب',
  'contacts.empty': 'هنوز مخاطبی ندارید.',
  'contacts.paste': 'کارت مخاطب را بچسبانید',
  'contacts.pasteHint': 'کارت مخاطب YSM را از او بگیرید و اینجا بچسبانید.',
  'contacts.addSubmit': 'افزودن مخاطب',
  'contacts.invalid': 'این یک کارت مخاطب معتبر YSM نیست.',
  'contacts.badSignature': 'امضای کارت معتبر نیست — ممکن است دستکاری شده باشد.',
  'contacts.myCard': 'کارت مخاطب من',
  'contacts.myCardHint': 'این را به طرف مقابل بدهید تا شما را اضافه کند.',
  'contacts.safetyTitle': 'شماره امنیتی',
  'contacts.safetyIntro':
    'این اعداد را با {name} حضوری یا با تماس صوتی مقایسه کنید. اگر یکسان بودند، هیچ‌کس پیام‌های شما را رهگیری نمی‌کند.',
  'contacts.markVerified': 'اعداد یکسان است — تأیید کن',
  'contacts.verifiedBadge': 'تأییدشده',
  'contacts.remove': 'حذف مخاطب',

  'file.selected': 'پیوست: {name}',
  'file.tooBig': 'این فایل بیش از حد بزرگ است (محدودیت {limit}).',
  'file.sending': 'در حال رمزنگاری {name}…',
  'file.save': 'ذخیره',
  'file.saved': 'ذخیره شد',
  'file.blocked': 'برای امنیت، این نوع فایل از داخل YSM باز نمی‌شود.',

  'settings.title': 'تنظیمات',
  'settings.language': 'زبان',
  'settings.account': 'حساب',
  'settings.displayName': 'نام نمایشی',
  'settings.security': 'امنیت',
  'settings.lockNow': 'همین حالا قفل کن',
  'settings.lockWarning': 'قفل کردن همه کلیدها را از حافظه پاک می‌کند. برای باز کردن دوباره به گذرواژه و کد احراز هویت نیاز دارید.',
  'settings.about': 'درباره',
  'settings.version': 'نسخه {version}',
  'settings.privacy': 'حریم خصوصی',
  'settings.privacyText':
    'YSM هیچ تله‌متری، هیچ تحلیل‌گر و هیچ سروری ندارد. هیچ کاری که در این برنامه انجام می‌دهید به جایی ارسال نمی‌شود. پیام‌ها فقط به‌صورت فایل رمزشده که خودتان خروجی می‌گیرید از دستگاه خارج می‌شوند.',
  'settings.noTelemetry': 'بدون تله‌متری. بدون سرور. بدون ردیابی.',
  'settings.autoLock': 'قفل خودکار پس از',
  'settings.autoLockSaved': 'قفل خودکار به‌روز شد',
  'settings.autoLockOff': 'هرگز',
  'settings.minutes': '{n} دقیقه',

  'error.generic': 'خطایی رخ داد.',
  'error.locked': 'مخزن قفل است.',
  'error.importFailed': 'این فایل وارد نشد: {reason}',
  'error.badEnvelope': 'این یک فایل رمزشده معتبر YSM نیست.',
  'error.keyMismatch': 'کلید فرستنده با مخاطب ذخیره‌شده یکسان نیست.',
  'error.unknownSender': 'پیام از فرستنده ناشناس.',

  'toast.messageSent': 'پیام رمزنگاری شد',
  'toast.fileImported': 'فایل وارد و رمزگشایی شد',
  'toast.contactAdded': 'مخاطب اضافه شد',
  'toast.contactVerified': 'مخاطب تأیید شد',
};

const nl: Dict = {
  'app.name': 'YSM',
  'app.tagline': 'Youtab Security Message',

  'nav.chats': 'Chats',
  'nav.crypto': 'Crypto',
  'nav.contacts': 'Contacten',
  'nav.settings': 'Instellingen',

  'crypto.writeTab': 'Versleutelen',
  'crypto.readTab': 'Ontsleutelen',
  'crypto.messageLabel': 'Bericht',
  'crypto.messagePlaceholder': 'Typ hier het bericht dat je wilt versleutelen…',
  'crypto.pickFile': 'Bestand kiezen',
  'crypto.writeHint': 'Je krijgt twee dingen: een referentie (YSM_…) en een wachtwoordzin. Stuur ze via verschillende kanalen.',
  'crypto.create': 'Create crypto',
  'crypto.resultTitle': 'Klaar — twee dingen om te versturen',
  'crypto.resultHint': 'Geef beide aan de lezer. Zonder de wachtwoordzin kan niemand het openen, ook jij niet.',
  'crypto.referenceLabel': 'Referentie',
  'crypto.referencePlaceholder': 'YSM_… (64 tekens)',
  'crypto.passphraseLabel': 'Wachtwoordzin',
  'crypto.passphraseWarning': 'De wachtwoordzin wordt nergens opgeslagen. Ben je hem kwijt, dan is dit bericht voorgoed onleesbaar.',
  'crypto.saveBlock': 'Download blok',
  'crypto.startOver': 'Opnieuw',
  'crypto.readHint': 'Plak de referentie, typ de wachtwoordzin en open.',
  'crypto.open': 'Ontsleutelen',
  'crypto.openedTitle': 'Ontsleuteld',
  'crypto.download': 'Bestand downloaden',

  'common.cancel': 'Annuleren',
  'common.save': 'Opslaan',
  'common.close': 'Sluiten',
  'common.copy': 'Kopiëren',
  'common.copied': 'Gekopieerd',
  'common.back': 'Terug',
  'common.next': 'Volgende',
  'common.done': 'Klaar',
  'common.delete': 'Verwijderen',
  'common.confirm': 'Bevestigen',
  'common.loading': 'Laden…',
  'common.optional': 'optioneel',
  'common.required': 'verplicht',
  'common.retry': 'Opnieuw proberen',

  'boot.title': 'Welkom bij YSM',
  'boot.subtitle': 'End-to-end versleutelde berichten die je apparaat nooit onversleuteld verlaten.',
  'boot.create': 'Nieuw account aanmaken',
  'boot.unlock': 'Bestaand account ontgrendelen',

  'create.title': 'Maak je account',
  'create.displayName': 'Weergavenaam',
  'create.displayNameHint': 'Zichtbaar voor je contacten. Later aanpasbaar.',
  'create.password': 'Wachtwoord',
  'create.passwordHint': 'Minimaal 12 tekens. Dit wachtwoord versleutelt alles op dit apparaat.',
  'create.passwordConfirm': 'Bevestig wachtwoord',
  'create.mismatch': 'Wachtwoorden komen niet overeen.',
  'create.submit': 'Account aanmaken',
  'create.working': 'Sleutels afleiden…',
  'create.weak': 'Dit wachtwoord is te zwak.',

  'onboard.title': 'Tweestapsverificatie instellen',
  'onboard.intro':
    'YSM vraagt elke keer een code uit je authenticator-app. Scan dit met Google Authenticator, Authy of een andere TOTP-app.',
  'onboard.secretLabel': 'Of voer deze sleutel handmatig in',
  'onboard.verifyLabel': 'Voer de 6-cijferige code uit je app in',
  'onboard.verify': 'Verifiëren en afronden',
  'onboard.recoveryTitle': 'Bewaar je herstelcodes',
  'onboard.recoveryIntro':
    'Als je je authenticator-app kwijtraakt, zijn dit de enige manieren om weer binnen te komen. Elke code werkt één keer. Bewaar ze veilig en offline.',
  'onboard.recoveryAck': 'Ik heb mijn herstelcodes opgeslagen',
  'onboard.copiedAll': 'Alle codes kopiëren',
  'onboard.downloadPdf': 'PDF downloaden',
  'onboard.downloadCsv': 'CSV downloaden',

  'unlock.title': 'YSM ontgrendelen',
  'unlock.password': 'Wachtwoord',
  'unlock.code': 'Authenticatorcode',
  'unlock.submit': 'Ontgrendelen',
  'unlock.working': 'Ontgrendelen…',
  'unlock.badPassword': 'Onjuist wachtwoord.',
  'unlock.badTotp': 'Onjuiste authenticatorcode.',
  'unlock.replay': 'Deze code is al gebruikt. Wacht op de volgende.',
  'unlock.lockedOut': 'Te veel pogingen. Probeer het over {seconds}s opnieuw.',
  'unlock.useRecovery': 'Een herstelcode gebruiken',
  'unlock.recoveryLabel': 'Herstelcode',

  'chats.empty': 'Nog geen gesprekken',
  'chats.emptyHint': 'Voeg een contact toe om een versleuteld gesprek te starten.',
  'chats.newChat': 'Nieuw gesprek',
  'chats.composerPlaceholder': 'Schrijf een bericht…',
  'chats.send': 'Versturen',
  'chats.attach': 'Bestand toevoegen',
  'chats.verified': 'Geverifieerd',
  'chats.unverified': 'Niet geverifieerd',
  'chats.noMessages': 'Nog geen berichten. Zeg hallo.',
  'chats.encrypted': 'End-to-end versleuteld',
  'chats.sendEnvelope': 'Versleuteld bestand exporteren',
  'chats.importEnvelope': 'Versleuteld bestand importeren',

  'contacts.title': 'Contacten',
  'contacts.add': 'Contact toevoegen',
  'contacts.empty': 'Nog geen contacten.',
  'contacts.paste': 'Plak de contactkaart',
  'contacts.pasteHint': 'Vraag om hun YSM-contactkaart en plak die hier.',
  'contacts.addSubmit': 'Contact toevoegen',
  'contacts.invalid': 'Dit is geen geldige YSM-contactkaart.',
  'contacts.badSignature': 'De handtekening van de kaart is ongeldig — mogelijk aangepast.',
  'contacts.myCard': 'Mijn contactkaart',
  'contacts.myCardHint': 'Deel dit zodat iemand jou kan toevoegen.',
  'contacts.safetyTitle': 'Veiligheidsnummer',
  'contacts.safetyIntro':
    'Vergelijk deze nummers met {name} persoonlijk of via een telefoongesprek. Komen ze overeen, dan onderschept niemand je berichten.',
  'contacts.markVerified': 'Nummers komen overeen — markeer als geverifieerd',
  'contacts.verifiedBadge': 'Geverifieerd',
  'contacts.remove': 'Contact verwijderen',

  'file.selected': 'Toegevoegd: {name}',
  'file.tooBig': 'Dit bestand is te groot (limiet {limit}).',
  'file.sending': '{name} versleutelen…',
  'file.save': 'Opslaan',
  'file.saved': 'Opgeslagen',
  'file.blocked': 'Dit bestandstype wordt om veiligheidsredenen niet binnen YSM geopend.',

  'settings.title': 'Instellingen',
  'settings.language': 'Taal',
  'settings.account': 'Account',
  'settings.displayName': 'Weergavenaam',
  'settings.security': 'Beveiliging',
  'settings.lockNow': 'Nu vergrendelen',
  'settings.lockWarning': 'Vergrendelen wist alle sleutels uit het geheugen. Je hebt je wachtwoord en authenticator nodig om weer te ontgrendelen.',
  'settings.about': 'Over',
  'settings.version': 'Versie {version}',
  'settings.privacy': 'Privacy',
  'settings.privacyText':
    'YSM heeft geen telemetrie, geen analyse en geen servers. Niets wat je in deze app doet wordt ergens naartoe gestuurd. Berichten verlaten je apparaat alleen als versleutelde bestanden die je zelf exporteert.',
  'settings.noTelemetry': 'Geen telemetrie. Geen servers. Geen tracking.',
  'settings.autoLock': 'Automatisch vergrendelen na',
  'settings.autoLockSaved': 'Vergrendeltijd bijgewerkt',
  'settings.autoLockOff': 'Nooit',
  'settings.minutes': '{n} minuten',

  'error.generic': 'Er ging iets mis.',
  'error.locked': 'De kluis is vergrendeld.',
  'error.importFailed': 'Dit bestand kon niet worden geïmporteerd: {reason}',
  'error.badEnvelope': 'Dit is geen geldig YSM-versleutelingsbestand.',
  'error.keyMismatch': 'De sleutel van de afzender komt niet overeen met het opgeslagen contact.',
  'error.unknownSender': 'Bericht van een onbekende afzender.',

  'toast.messageSent': 'Bericht versleuteld',
  'toast.fileImported': 'Bestand geïmporteerd en ontsleuteld',
  'toast.contactAdded': 'Contact toegevoegd',
  'toast.contactVerified': 'Contact gemarkeerd als geverifieerd',
};

const DICTS: Record<Locale, Dict> = { en, fa, nl };

/** Keys that must exist. Used by the test suite to catch missing translations. */
export const REFERENCE_KEYS: readonly string[] = Object.keys(en);

export type TranslateVars = Record<string, string | number>;

/** Look up a key, substitute `{name}` placeholders. */
export function translate(locale: Locale, key: string, vars?: TranslateVars): string {
  const dict = DICTS[locale] ?? en;
  let template = dict[key];
  if (template === undefined) {
    // Fall back to English rather than showing a raw key, but this is caught by
    // the translation test, so it should never reach a user in practice.
    template = en[key] ?? key;
  }
  if (vars === undefined) return template;
  return template.replace(/\{(\w+)\}/g, (match, name: string) => {
    const value = vars[name];
    return value === undefined ? match : String(value);
  });
}

/** Which keys are missing from a given locale (used by tests). */
export function missingKeys(locale: Locale): string[] {
  const dict = DICTS[locale];
  return REFERENCE_KEYS.filter((k) => dict[k] === undefined);
}
