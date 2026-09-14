package detector

import "regexp"

// Rule defines a secret detection signature.
type Rule struct {
	ID             string
	Provider       string
	Description    string
	Regex          *regexp.Regexp
	RequiredSubstr string  // Substring that must be present (speed optimization)
	MinEntropy     float64 // Minimum Shannon entropy required to avoid false positives
	VerifyType     string  // Key identifier for live verification
}

// GetRules returns the standard database of secret detection signatures.
func GetRules() []Rule {
	return []Rule{
		{
			ID:             "openai-project-key",
			Provider:       "OpenAI",
			Description:    "OpenAI Modern Project API Key (with unique Base64 signature)",
			Regex:          regexp.MustCompile(`sk-proj-[A-Za-z0-9_-]{8,}T3BlbkFJ[A-Za-z0-9_-]{8,}`),
			RequiredSubstr: "T3BlbkFJ",
			MinEntropy:     3.0,
			VerifyType:     "openai",
		},
		{
			ID:             "openai-legacy-key",
			Provider:       "OpenAI",
			Description:    "OpenAI Standard User API Key",
			Regex:          regexp.MustCompile(`\bsk-[A-Za-z0-9]{48}\b`),
			RequiredSubstr: "sk-",
			MinEntropy:     3.5,
			VerifyType:     "openai",
		},
		{
			ID:             "anthropic-api-key",
			Provider:       "Anthropic",
			Description:    "Anthropic Claude API Key (v3 standard)",
			Regex:          regexp.MustCompile(`sk-ant-api03-[A-Za-z0-9_-]{80,110}`),
			RequiredSubstr: "sk-ant-api03-",
			MinEntropy:     3.5,
			VerifyType:     "anthropic",
		},
		{
			ID:             "aws-access-key-id",
			Provider:       "AWS",
			Description:    "Amazon Web Services IAM Access Key ID",
			Regex:          regexp.MustCompile(`\b(AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b`),
			MinEntropy:     2.8,
			VerifyType:     "aws",
		},
		{
			ID:             "stripe-live-secret-key",
			Provider:       "Stripe",
			Description:    "Stripe Live Production Secret Key",
			Regex:          regexp.MustCompile(`\bsk_live_[0-9a-zA-Z]{24,99}\b`),
			RequiredSubstr: "sk_live_",
			MinEntropy:     3.0,
			VerifyType:     "stripe",
		},
		{
			ID:             "stripe-restricted-key",
			Provider:       "Stripe",
			Description:    "Stripe Restricted Live Secret Key",
			Regex:          regexp.MustCompile(`\brk_live_[0-9a-zA-Z]{24,99}\b`),
			RequiredSubstr: "rk_live_",
			MinEntropy:     3.0,
			VerifyType:     "stripe",
		},
		{
			ID:             "github-pat-classic",
			Provider:       "GitHub",
			Description:    "GitHub Personal Access Token (Classic)",
			Regex:          regexp.MustCompile(`\bghp_[0-9a-zA-Z]{36}\b`),
			RequiredSubstr: "ghp_",
			MinEntropy:     3.2,
			VerifyType:     "github",
		},
		{
			ID:             "github-pat-fine-grained",
			Provider:       "GitHub",
			Description:    "GitHub Fine-Grained Personal Access Token",
			Regex:          regexp.MustCompile(`\bgithub_pat_[0-9a-zA-Z_]{82}\b`),
			RequiredSubstr: "github_pat_",
			MinEntropy:     3.5,
			VerifyType:     "github",
		},
		{
			ID:             "huggingface-token",
			Provider:       "HuggingFace",
			Description:    "HuggingFace User Access Token",
			Regex:          regexp.MustCompile(`\bhf_[0-9a-zA-Z]{34}\b`),
			RequiredSubstr: "hf_",
			MinEntropy:     3.2,
			VerifyType:     "huggingface",
		},
		{
			ID:             "slack-bot-token",
			Provider:       "Slack",
			Description:    "Slack Bot User OAuth Token",
			Regex:          regexp.MustCompile(`\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}\b`),
			RequiredSubstr: "xoxb-",
			MinEntropy:     2.9,
			VerifyType:     "slack",
		},
		{
			ID:             "google-gemini-key",
			Provider:       "Google",
			Description:    "Google AI Studio / Gemini API Key",
			Regex:          regexp.MustCompile(`\bAIzaSy[A-Za-z0-9_-]{33}\b`),
			RequiredSubstr: "AIzaSy",
			MinEntropy:     3.3,
			VerifyType:     "google",
		},
		{
			ID:             "groq-api-key",
			Provider:       "Groq",
			Description:    "Groq Cloud Inference API Key",
			Regex:          regexp.MustCompile(`\bgsk_[a-zA-Z0-9]{52}\b`),
			RequiredSubstr: "gsk_",
			MinEntropy:     3.4,
			VerifyType:     "groq",
		},
		{
			ID:             "pinecone-api-key",
			Provider:       "Pinecone",
			Description:    "Pinecone Vector Database API Key",
			Regex:          regexp.MustCompile(`\bpcsk_[a-zA-Z0-9_-]{48,70}\b`),
			RequiredSubstr: "pcsk_",
			MinEntropy:     3.3,
			VerifyType:     "pinecone",
		},
		{
			ID:             "resend-api-key",
			Provider:       "Resend",
			Description:    "Resend Email Platform API Key",
			Regex:          regexp.MustCompile(`\bre_[a-zA-Z0-9]{32,48}\b`),
			RequiredSubstr: "re_",
			MinEntropy:     3.0,
			VerifyType:     "resend",
		},
		{
			ID:             "sendgrid-api-key",
			Provider:       "SendGrid",
			Description:    "SendGrid API Authentication Token",
			Regex:          regexp.MustCompile(`\bSG\.[0-9a-zA-Z_-]{22}\.[0-9a-zA-Z_-]{43}\b`),
			RequiredSubstr: "SG.",
			MinEntropy:     3.5,
			VerifyType:     "sendgrid",
		},
		{
			ID:             "discord-bot-token",
			Provider:       "Discord",
			Description:    "Discord Bot Authorization Token",
			Regex:          regexp.MustCompile(`\b[MN][A-Za-z0-9]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38}\b`),
			MinEntropy:     3.2,
			VerifyType:     "discord",
		},
		{
			ID:             "postman-api-key",
			Provider:       "Postman",
			Description:    "Postman API Access Key",
			Regex:          regexp.MustCompile(`\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b`),
			RequiredSubstr: "PMAK-",
			MinEntropy:     3.0,
			VerifyType:     "postman",
		},
		{
			ID:             "telegram-bot-token",
			Provider:       "Telegram",
			Description:    "Telegram Bot API Token",
			Regex:          regexp.MustCompile(`\b[0-9]{9,10}:[a-zA-Z0-9_-]{35}\b`),
			MinEntropy:     3.1,
			VerifyType:     "telegram",
		},
		{
			ID:             "sentry-auth-token",
			Provider:       "Sentry",
			Description:    "Sentry Authentication User Token",
			Regex:          regexp.MustCompile(`\bsntrys_[a-f0-9]{64}\b`),
			RequiredSubstr: "sntrys_",
			MinEntropy:     2.8,
			VerifyType:     "sentry",
		},
	}
}
