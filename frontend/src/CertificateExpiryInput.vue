<script setup lang="ts">
import { t } from './i18n'
import FloatingField from './FloatingField.vue'
import { utcToday, defaultCertificateDate } from './certificateDates'
const value = defineModel<string>({ default: () => defaultCertificateDate() })
defineProps<{ id: string; max?: string }>()
</script>
<template>
  <FloatingField class="certificate-expiry-field" :id="id" :label="t('certificate.certificateExpirationDateUTC')" fixed>
    <input :id="id" v-model="value" type="date" :min="utcToday()" :max="max || undefined">
  </FloatingField>
</template>
<style scoped>
.certificate-expiry-field { margin: 16px 0 0; }
</style>
