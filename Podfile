platform :ios, '11.0'
use_frameworks!

# ignore all warnings from all pods
inhibit_all_warnings!

abstract_target 'PIATunnel' do
    pod 'SwiftyBeaver', '~> 1.7.0'
    pod 'OpenSSL-Universal', "~> 1.1.0i"

    target 'PIATunnel-iOS' do
        platform :ios, '11.0'
    end
    target 'PIATunnelHost' do
        platform :ios, '11.0'
    end

    target 'PIATunnel-macOS' do
        platform :osx, '10.11'
    end
end
