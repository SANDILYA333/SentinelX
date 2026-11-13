"""Living-off-the-Land (LotL) Deception artifact content generators."""

from sentinelx.deception.lotl.lures.config_files import get_config_file_content
from sentinelx.deception.lotl.lures.env_vars import get_canary_env_content
from sentinelx.deception.lotl.lures.scheduled_tasks import (
    get_decoy_cron_content,
    get_inert_script_content,
)
from sentinelx.deception.lotl.lures.shares import get_share_file_content
from sentinelx.deception.lotl.lures.shell_history import get_shell_history_content
from sentinelx.deception.lotl.lures.ssh_keys import (
    get_decoy_ssh_config_content,
    get_decoy_ssh_key_content,
)
from sentinelx.deception.lotl.lures.windows_history import (
    get_powershell_history_content,
)

__all__ = [
    "get_canary_env_content",
    "get_config_file_content",
    "get_decoy_cron_content",
    "get_decoy_ssh_config_content",
    "get_decoy_ssh_key_content",
    "get_inert_script_content",
    "get_powershell_history_content",
    "get_share_file_content",
    "get_shell_history_content",
]

