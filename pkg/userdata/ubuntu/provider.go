/*
Copyright 2019 The Machine Controller Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

//
// UserData plugin for Ubuntu.
//

package ubuntu

import (
    "bytes"
    "errors"
    "fmt"
    "text/template"

    "github.com/Masterminds/semver"

    "github.com/kubermatic/machine-controller/pkg/apis/plugin"
    providerconfigtypes "github.com/kubermatic/machine-controller/pkg/providerconfig/types"
    userdatahelper "github.com/kubermatic/machine-controller/pkg/userdata/helper"
)

// Provider is a pkg/userdata/plugin.Provider implementation.
type Provider struct{}

// UserData renders user-data template to string.
func (p Provider) UserData(req plugin.UserDataRequest) (string, error) {

    tmpl, err := template.New("user-data").Funcs(userdatahelper.TxtFuncMap()).Parse(userDataTemplate)
    if err != nil {
        return "", fmt.Errorf("failed to parse user-data template: %v", err)
    }

    kubeletVersion, err := semver.NewVersion(req.MachineSpec.Versions.Kubelet)
    if err != nil {
        return "", fmt.Errorf("invalid kubelet version: %v", err)
    }

    dockerVersion, err := userdatahelper.DockerVersionApt(kubeletVersion)
    if err != nil {
        return "", fmt.Errorf("invalid docker version: %v", err)
    }

    pconfig, err := providerconfigtypes.GetConfig(req.MachineSpec.ProviderSpec)
    if err != nil {
        return "", fmt.Errorf("failed to get providerSpec: %v", err)
    }

    if pconfig.OverwriteCloudConfig != nil {
        req.CloudConfig = *pconfig.OverwriteCloudConfig
    }

    if pconfig.Network != nil {
        return "", errors.New("static IP config is not supported with Ubuntu")
    }

    ubuntuConfig, err := LoadConfig(pconfig.OperatingSystemSpec)
    if err != nil {
        return "", fmt.Errorf("failed to get ubuntu config from provider config: %v", err)
    }

    serverAddr, err := userdatahelper.GetServerAddressFromKubeconfig(req.Kubeconfig)
    if err != nil {
        return "", fmt.Errorf("error extracting server address from kubeconfig: %v", err)
    }

    kubeconfigString, err := userdatahelper.StringifyKubeconfig(req.Kubeconfig)
    if err != nil {
        return "", err
    }

    kubernetesCACert, err := userdatahelper.GetCACert(req.Kubeconfig)
    if err != nil {
        return "", fmt.Errorf("error extracting cacert: %v", err)
    }

    data := struct {
        plugin.UserDataRequest
        ProviderSpec     *providerconfigtypes.Config
        OSConfig         *Config
        ServerAddr       string
        KubeletVersion   string
        DockerVersion    string
        Kubeconfig       string
        KubernetesCACert string
        NodeIPScript     string
    }{
        UserDataRequest:  req,
        ProviderSpec:     pconfig,
        OSConfig:         ubuntuConfig,
        ServerAddr:       serverAddr,
        KubeletVersion:   kubeletVersion.String(),
        DockerVersion:    dockerVersion,
        Kubeconfig:       kubeconfigString,
        KubernetesCACert: kubernetesCACert,
        NodeIPScript:     userdatahelper.SetupNodeIPEnvScript(),
    }
    b := &bytes.Buffer{}
    err = tmpl.Execute(b, data)
    if err != nil {
        return "", fmt.Errorf("failed to execute user-data template: %v", err)
    }
    return userdatahelper.CleanupTemplateOutput(b.String())
}

// UserData template.
const userDataTemplate = `#cloud-config
{{ if ne .CloudProviderName "aws" }}
hostname: {{ .MachineSpec.Name }}
{{- /* Never set the hostname on AWS nodes. Kubernetes(kube-proxy) requires the hostname to be the private dns name */}}
{{ end }}

{{- if .OSConfig.DistUpgradeOnBoot }}
package_upgrade: true
package_reboot_if_required: true
{{- end }}

ssh_pwauth: no

swap:
  filename: /swap.img
  size: "3221225472"
  maxsize: "3221225472"

{{- if .ProviderSpec.SSHPublicKeys }}
ssh_authorized_keys:
{{- range .ProviderSpec.SSHPublicKeys }}
- "{{ . }}"
{{- end }}
{{- end }}

write_files:
{{- if .HTTPProxy }}
- path: "/etc/environment"
  content: |
    PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games"
{{ proxyEnvironment .HTTPProxy .NoProxy | indent 4 }}
{{- end }}

- path: "/etc/systemd/journald.conf.d/max_disk_use.conf"
  content: |
{{ journalDConfig | indent 4 }}

- path: "/opt/bin/setup"
  permissions: "0755"
  content: |
    #!/bin/bash
    set -xeuo pipefail

    DEBIAN_FRONTEND=noninteractive apt-get -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" install -y \
      curl \
      {{- if eq .CloudProviderName "vsphere" }}
      open-vm-tools \
      {{- end }}

    PUBLIC_IP_ADDRESS=$(curl ifconfig.co)

    DEBIAN_FRONTEND=noninteractive apt autoremove -y --purge snapd

    curl -sfL https://get.k3s.io | K3S_URL={{ .K3SURL }} K3S_TOKEN={{ .K3SToken }} sh -s - --node-external-ip=$PUBLIC_IP_ADDRESS {{ if .ExternalCloudProvider }} --kubelet-arg=cloud-provider=external {{ end }}

- path: "/opt/bin/supervise.sh"
  permissions: "0755"
  content: |
    #!/bin/bash
    set -xeuo pipefail
    while ! "$@"; do
      sleep 1
    done

- path: "/etc/systemd/system/setup.service"
  permissions: "0644"
  content: |
    [Install]
    WantedBy=multi-user.target

    [Unit]
    Requires=network-online.target
    After=network-online.target

    [Service]
    Type=oneshot
    RemainAfterExit=true
    EnvironmentFile=-/etc/environment
    ExecStart=/opt/bin/supervise.sh /opt/bin/setup

- path: "/etc/profile.d/opt-bin-path.sh"
  permissions: "0644"
  content: |
    export PATH="/opt/bin:$PATH"

runcmd:
- systemctl start setup.service
`
