/// ShieldConfigurationExtension.swift
/// Shield Configuration Extension — customizes the blocking screen shown
/// when a user tries to open a blocked app or website.
///
/// This is a separate Xcode target of type "Shield Configuration Extension".
/// It has no access to the main app's state — customize only via static content.

import ManagedSettings
import ManagedSettingsUI
import UIKit

class ShieldConfigurationExtension: ShieldConfigurationDataSource {

    /// Customize the shield shown when a blocked app is opened.
    override func configuration(shielding application: Application) -> ShieldConfiguration {
        ShieldConfiguration(
            backgroundBlurStyle: .systemUltraThinMaterialDark,
            backgroundColor: UIColor(red: 0.05, green: 0.05, blue: 0.1, alpha: 0.95),
            icon: UIImage(systemName: "lock.fill"),
            title: ShieldConfiguration.Label(
                text: "专注时间",
                color: .white
            ),
            subtitle: ShieldConfiguration.Label(
                text: "此应用在专注时段已被屏蔽",
                color: UIColor.white.withAlphaComponent(0.7)
            ),
            primaryButtonLabel: ShieldConfiguration.Label(
                text: "我知道了",
                color: .white
            ),
            primaryButtonBackgroundColor: UIColor(red: 0.2, green: 0.2, blue: 0.3, alpha: 1)
        )
    }

    /// Customize the shield shown when a blocked website is opened.
    override func configuration(shielding webDomain: WebDomain) -> ShieldConfiguration {
        ShieldConfiguration(
            backgroundBlurStyle: .systemUltraThinMaterialDark,
            backgroundColor: UIColor(red: 0.05, green: 0.05, blue: 0.1, alpha: 0.95),
            icon: UIImage(systemName: "hand.raised.fill"),
            title: ShieldConfiguration.Label(
                text: "网站已屏蔽",
                color: .white
            ),
            subtitle: ShieldConfiguration.Label(
                text: webDomain.domain.map { "已屏蔽: \($0)" } ?? "此网站在专注时段已被屏蔽",
                color: UIColor.white.withAlphaComponent(0.7)
            ),
            primaryButtonLabel: ShieldConfiguration.Label(
                text: "返回",
                color: .white
            ),
            primaryButtonBackgroundColor: UIColor(red: 0.2, green: 0.2, blue: 0.3, alpha: 1)
        )
    }

    /// Customize the shield shown when a blocked app category is opened.
    override func configuration(shielding application: Application,
                                in category: ActivityCategory) -> ShieldConfiguration {
        ShieldConfiguration(
            backgroundBlurStyle: .systemUltraThinMaterialDark,
            backgroundColor: UIColor(red: 0.05, green: 0.05, blue: 0.1, alpha: 0.95),
            icon: UIImage(systemName: "lock.fill"),
            title: ShieldConfiguration.Label(
                text: "专注时间",
                color: .white
            ),
            subtitle: ShieldConfiguration.Label(
                text: "此类应用在专注时段已被屏蔽",
                color: UIColor.white.withAlphaComponent(0.7)
            ),
            primaryButtonLabel: ShieldConfiguration.Label(
                text: "我知道了",
                color: .white
            ),
            primaryButtonBackgroundColor: UIColor(red: 0.2, green: 0.2, blue: 0.3, alpha: 1)
        )
    }
}
