from swm_sdk import CheckUpdateOptions, Client, ClientOptions


def main() -> None:
    options = ClientOptions(
        base_url="https://swm-backend.anteasy.com",
        app_id="00000000-0000-0000-0000-000000000001",
        release_id="00000000-0000-0000-0000-000000000002",
        version="1.0.0",
        root_trust_key_id="root-1",
        root_trust_public_key="00" * 32,
    )
    with Client(options) as client:
        update = client.check_update(CheckUpdateOptions())
        print(f"update_available={update.update_available}")


if __name__ == "__main__":
    main()
