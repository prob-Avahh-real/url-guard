/** Curated signals for offline URL risk scoring. */

export const SUSPICIOUS_TLDS = new Set([
  'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'vip', 'work', 'click',
  'loan', 'men', 'date', 'racing', 'download', 'stream', 'zip', 'mov',
  'country', 'kim', 'rest', 'quest', 'cfd', 'sbs', 'cyou', 'icu',
]);

/** Well-known brands often impersonated (ASCII forms). */
export const BRANDS = [
  'google', 'gmail', 'youtube', 'facebook', 'instagram', 'twitter', 'x',
  'microsoft', 'apple', 'icloud', 'amazon', 'paypal', 'ebay', 'netflix',
  'whatsapp', 'telegram', 'linkedin', 'github', 'dropbox', 'adobe',
  'binance', 'coinbase', 'metamask', 'opensea',
  'alipay', 'taobao', 'tmall', 'jd', 'wechat', 'weixin', 'qq', 'baidu',
  'icbc', 'ccb', 'abc', 'boc', 'cmb', 'unionpay', 'tenpay',
  'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'hsbc',
];

/** Official / high-trust registrable domains (allowlist seed). */
export const TRUSTED_DOMAINS = [
  'google.com', 'google.com.hk', 'gmail.com', 'youtube.com',
  'microsoft.com', 'live.com', 'office.com', 'apple.com', 'icloud.com',
  'amazon.com', 'amazon.cn', 'paypal.com', 'ebay.com', 'netflix.com',
  'facebook.com', 'instagram.com', 'twitter.com', 'x.com',
  'github.com', 'gitlab.com', 'stackoverflow.com',
  'alipay.com', 'taobao.com', 'tmall.com', 'jd.com', 'qq.com',
  'weixin.qq.com', 'baidu.com', 'bilibili.com',
  'icbc.com.cn', 'ccb.com', 'abchina.com', 'boc.cn', 'cmbchina.com',
  'unionpay.com', 'chinaums.com',
  'binance.com', 'coinbase.com',
  'wikipedia.org',
  // NOTE: never seed bare public suffixes like edu.cn / gov.cn — that allowlists entire trees.
];

/** Hostname / path tokens common in gambling / betting fronts. */
export const GAMBLING_TOKENS = [
  'casino', 'betting', 'bet365', 'poker', 'slot', 'slots', 'jackpot',
  'baccarat', 'roulette', 'lottery', 'wager', 'sportsbook', 'odds',
  'bocai', 'bocaiwang', 'caipiao', 'liuhe', 'liuhecai', 'shishicai',
  'pankou', 'yulecheng', 'duchang', 'touzhu', 'kaijiang',
  '威尼斯人', '太阳城', '澳门赌场', '六合彩', '时时彩', '博彩',
  '皇冠娱乐', '金沙娱乐', '永利',
];

/** Phishing / credential-harvest path or host tokens. */
export const PHISHING_TOKENS = [
  'login', 'signin', 'sign-in', 'log-in', 'verify', 'verification',
  'secure', 'security', 'account', 'update', 'confirm', 'unlock',
  'suspend', 'limited', 'restore', 'wallet', 'seed', 'mnemonic',
  'airdrop', 'claim', 'password', 'credential', 'auth', 'oauth',
  '重置', '验证', '安全中心', '账户异常', '冻结', '解冻', '中奖',
];

/** Fraud / scam marketing tokens. */
export const FRAUD_TOKENS = [
  'free-iphone', 'get-rich', 'double-money', 'invest-now', 'guaranteed-profit',
  'crypto-gift', 'claim-reward', 'act-now', 'limited-offer',
  '刷单', '返利', '高收益', '稳赚', '内幕', '代操', '杀猪盘',
  '资金盘', '传销', '中奖通知', '领奖',
];

/** Common homoglyph substitutions for brand checks. */
export const HOMOGLYPHS = {
  '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't',
  '@': 'a', '$': 's', '!': 'i',
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
  'і': 'i', 'ѕ': 's',
};
