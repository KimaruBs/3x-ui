import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Modal, Button, Descriptions, Tag, Alert, Space } from 'antd';
import { CloudDownloadOutlined, CheckCircleOutlined, SyncOutlined } from '@ant-design/icons';

import { HttpUtil } from '@/utils';
import { formatPanelVersion } from '@/lib/panel-version';

export interface BotUpdateInfo {
  installed: boolean;
  currentVersion: string;
  latestVersion: string;
  updateAvailable: boolean;
}

interface BotUpdateModalProps {
  open: boolean;
  info: BotUpdateInfo;
  onClose: () => void;
  onUpdated: (info: BotUpdateInfo) => void;
  onBusy: (state: { busy: boolean; tip?: string }) => void;
}

export default function BotUpdateModal({ open, info, onClose, onUpdated, onBusy }: BotUpdateModalProps) {
  const { t } = useTranslation();
  const [updating, setUpdating] = useState(false);
  const [error, setError] = useState('');

  async function handleUpdate() {
    setUpdating(true);
    setError('');
    onBusy({ busy: true, tip: t('pages.index.updatingBot') });
    try {
      // Бэкенду нужно: git pull/checkout последнего релиза xray-bot,
      // переустановка venv-зависимостей (requirements.txt), рестарт сервиса.
      const res = await HttpUtil.post<BotUpdateInfo>('/panel/api/server/updateBot');
      if (res?.success && res.obj) {
        onUpdated(res.obj);
        onClose();
      } else {
        setError(res?.msg || t('somethingWentWrong'));
      }
    } catch (e) {
      setError(t('somethingWentWrong'));
    } finally {
      setUpdating(false);
      onBusy({ busy: false });
    }
  }

  return (
    <Modal
      open={open}
      title={t('pages.index.updateBot')}
      onCancel={onClose}
      footer={[
        <Button key="close" onClick={onClose} disabled={updating}>
          {t('close')}
        </Button>,
        <Button
          key="update"
          type="primary"
          danger={info.updateAvailable}
          icon={updating ? <SyncOutlined spin /> : <CloudDownloadOutlined />}
          loading={updating}
          disabled={!info.installed}
          onClick={handleUpdate}
        >
          {info.updateAvailable ? t('update') : t('pages.index.reinstallBot')}
        </Button>,
      ]}
    >
      {!info.installed ? (
        <Alert
          type="warning"
          showIcon
          message={t('pages.index.botNotInstalled')}
          description={t('pages.index.botNotInstalledHint')}
        />
      ) : (
        <>
          <Descriptions column={1} bordered size="small">
            <Descriptions.Item label={t('pages.index.currentVersion')}>
              {formatPanelVersion(info.currentVersion) || '?'}
            </Descriptions.Item>
            <Descriptions.Item label={t('pages.index.latestVersion')}>
              <Space>
                {formatPanelVersion(info.latestVersion) || '?'}
                {info.updateAvailable ? (
                  <Tag color="orange">{t('pages.index.updateAvailable')}</Tag>
                ) : (
                  <Tag icon={<CheckCircleOutlined />} color="green">
                    {t('pages.index.upToDate')}
                  </Tag>
                )}
              </Space>
            </Descriptions.Item>
          </Descriptions>

          {error && (
            <Alert style={{ marginTop: 12 }} type="error" showIcon message={error} />
          )}

          {info.updateAvailable && (
            <Alert
              style={{ marginTop: 12 }}
              type="info"
              showIcon
              message={t('pages.index.botUpdateWarning')}
            />
          )}
        </>
      )}
    </Modal>
  );
}
