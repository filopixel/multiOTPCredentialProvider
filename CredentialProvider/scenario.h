#pragma once

// Simplified field IDs for daemon stub credential provider
enum FIELD_ID
{
	FID_LOGO = 0,
	FID_LARGE_TEXT = 1,
	FID_SMALL_TEXT = 2,
	FID_USERNAME = 3,
	FID_LDAP_PASS = 4,
	FID_OTP = 5,
	FID_SUBMIT_BUTTON = 6,
	FID_NUM_FIELDS = 7
};

// The first value indicates when the tile is displayed (selected, not selected)
// the second indicates things like whether the field is enabled, whether it has key focus, etc.
struct FIELD_STATE_PAIR
{
	// Source : https://docs.microsoft.com/en-us/windows/win32/api/credentialprovider/ne-credentialprovider-credential_provider_field_state
	CREDENTIAL_PROVIDER_FIELD_STATE cpfs; // Allowed values CPFS_HIDDEN, CPFS_DISPLAY_IN_SELECTED_TILE, CPFS_DISPLAY_IN_DESELECTED_TILE, CPFS_DISPLAY_IN_BOTH
	CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE cpfis; // Allowed values : CPFIS_NONE, CPFIS_READONLY, CPFIS_DISABLED, CPFIS_FOCUSED
};

// Scenario: LOGON/UNLOCK/CREDUI - All fields editable (user types everything)
// Used for local logon, unlock fallback, and UAC/RunAs
static const FIELD_STATE_PAIR s_rgScenarioLogon[] =
{
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// FID_LOGO
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// FID_LARGE_TEXT
	{ CPFS_HIDDEN, CPFIS_NONE },							// FID_SMALL_TEXT
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED },		// FID_USERNAME (editable)
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// FID_LDAP_PASS (editable)
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// FID_OTP (editable)
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// FID_SUBMIT_BUTTON
};

// Scenario: RDP/NLA - Username visible (disabled), password HIDDEN, only OTP editable
// NLA credentials are stored in config for serialization but password field is not shown
static const FIELD_STATE_PAIR s_rgScenarioLogonSerialized[] =
{
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// FID_LOGO
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// FID_LARGE_TEXT
	{ CPFS_HIDDEN, CPFIS_NONE },							// FID_SMALL_TEXT
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_DISABLED },		// FID_USERNAME (from NLA, visible but disabled)
	{ CPFS_HIDDEN, CPFIS_NONE },							// FID_LDAP_PASS (from NLA, HIDDEN)
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED },		// FID_OTP (editable, focused)
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// FID_SUBMIT_BUTTON
};

// Field descriptors for unlock and logon.
// The first field is the index of the field.
// The second is the type of the field.
// The third is the name of the field, NOT the value which will appear in the field.
static CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_rgScenarioCredProvFieldDescriptors[] =
{
	{ FID_LOGO, CPFT_TILE_IMAGE, L"Daemon Stub Login" },
	{ FID_LARGE_TEXT, CPFT_LARGE_TEXT, L"LargeText" },
	{ FID_SMALL_TEXT, CPFT_SMALL_TEXT, L"SmallText" },
	{ FID_USERNAME, CPFT_EDIT_TEXT, L"Username" },
	{ FID_LDAP_PASS, CPFT_PASSWORD_TEXT, L"Password" },
	{ FID_OTP, CPFT_EDIT_TEXT, L"One-Time Password" },
	{ FID_SUBMIT_BUTTON, CPFT_SUBMIT_BUTTON, L"Submit" },
};
