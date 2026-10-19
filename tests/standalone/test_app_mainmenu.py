# In this test we check the behavior of the device main menu
def test_app_mainmenu(navigator, test_name, default_screenshot_path):
    # Home screen only. Warthog has no settings switches.
    instructions = []
    navigator.navigate_and_compare(
        default_screenshot_path,
        test_name,
        instructions,
        screen_change_before_first_instruction=False,
    )
