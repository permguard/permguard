<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<!--
  The plane in view, in the bar: inside a plane's pages the bar names that plane, with its icon,
  after the Planes menu; anywhere else it names nothing. A stub left at an old address under
  `how-it-works/` is not a plane's page, so it shows nothing either. The phone's menu shows nothing:
  there Planes already opens on the plane in view, and the page's own sidebar lists the planes.
-->
<script setup lang="ts">
import { computed } from 'vue'
import { useRoute, withBase } from 'vitepress'

const props = defineProps<{ screenMenu?: boolean }>()

const planes = [
  { slug: 'authority-plane', name: 'Authority Plane' },
  { slug: 'control-plane', name: 'Control Plane' },
  { slug: 'data-plane', name: 'Data Plane' }
]

const route = useRoute()

const current = computed(() => {
  if (props.screenMenu) return undefined
  const path = route.path
  if (path.includes('/how-it-works/')) return undefined
  return planes.find((plane) => new RegExp(`/${plane.slug}(?:\\.html)?(?:/|$)`).test(path))
})
</script>

<template>
  <a
    v-if="current"
    class="pg-current-plane active"
    :class="props.screenMenu ? 'VPNavScreenMenuLink' : 'VPNavBarMenuLink'"
    :data-plane="current.slug"
    :href="withBase(`/${current.slug}`)"
    aria-current="page"
  ><span>{{ current.name }}</span></a>
</template>
