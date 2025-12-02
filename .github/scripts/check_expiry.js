const { createClient } = require('@supabase/supabase-js');
const { Resend } = require('resend');

const supabaseUrl = process.env.SUPABASE_URL;
// 必须用 Service Role Key，否则无法读取所有用户信息
const supabaseKey = process.env.SUPABASE_SERVICE_KEY;
const resendKey = process.env.RESEND_API_KEY;

const supabase = createClient(supabaseUrl, supabaseKey);
const resend = new Resend(resendKey);

async function checkAndSend() {
  console.log('🔄 开始执行每日检查...');

  // 1. 获取所有用户 (为了拿到他们的 notify_email)
  // listUsers 需要 service_role 权限
  const { data: { users }, error: userError } = await supabase.auth.admin.listUsers();
  
  if (userError) {
    console.error('❌ 获取用户列表失败:', userError);
    return;
  }

  // 建立一个映射表: user_id -> 真实邮箱
  const userMap = {};
  users.forEach(u => {
    if (u.user_metadata && u.user_metadata.notify_email) {
      userMap[u.id] = u.user_metadata.notify_email;
    }
  });

  // 2. 获取所有物品
  const { data: items, error: itemError } = await supabase.from('cycle_items').select('*');
  
  if (itemError) {
    console.error('❌ 获取物品失败:', itemError);
    return;
  }

  // 3. 筛选并按用户分组
  // 结构: { "user_id_A": [item1, item2], "user_id_B": [item3] }
  const alerts = {};

  items.forEach(item => {
    // 如果这个物品的主人没有设置接收邮箱，就跳过
    const targetEmail = userMap[item.user_id];
    if (!targetEmail) return;

    // 计算是否过期
    const start = new Date(item.start_date);
    const end = new Date(start);
    if (item.unit === 'days') end.setDate(start.getDate() + parseInt(item.duration));
    if (item.unit === 'months') end.setMonth(start.getMonth() + parseInt(item.duration));
    if (item.unit === 'years') end.setFullYear(start.getFullYear() + parseInt(item.duration));

    const now = new Date();
    const daysLeft = Math.ceil((end - now) / (1000 * 60 * 60 * 24));

    // 逻辑：剩余3天内，或者过期7天内
    if (daysLeft <= 3 && daysLeft >= -7) {
      if (!alerts[item.user_id]) {
        alerts[item.user_id] = { email: targetEmail, items: [] };
      }
      alerts[item.user_id].items.push({
        name: item.name,
        days: daysLeft,
        date: end.toLocaleDateString()
      });
    }
  });

  // 4. 分别发送邮件
  const userIds = Object.keys(alerts);
  if (userIds.length === 0) {
    console.log('✅ 没有需要提醒的用户。');
    return;
  }

  console.log(`📧 准备给 ${userIds.length} 位用户发送提醒...`);

  for (const uid of userIds) {
    const userAlert = alerts[uid];
    const emailTo = userAlert.email;
    const itemList = userAlert.items;

    let htmlContent = `<h2>Cycle 物品提醒</h2><p>你好，你有以下物品需要关注：</p><ul>`;
    itemList.forEach(i => {
        const color = i.days < 0 ? 'red' : 'orange';
        const status = i.days < 0 ? `已过期 ${Math.abs(i.days)} 天` : `剩余 ${i.days} 天`;
        htmlContent += `<li><strong>${i.name}</strong>: <span style="color:${color}">${status}</span> (${i.date} 到期)</li>`;
    });
    htmlContent += `</ul><p><a href="https://tools.gimago.cn/cycle">点击查看详情</a></p>`;

    try {
      await resend.emails.send({
        from: 'Cycle <notify@gimago.cn>', // ⚠️ 这里要填你验证过的域名邮箱，比如 noreply@gimago.cn
        to: [emailTo],
        subject: `【提醒】${itemList.length} 个物品即将过期`,
        html: htmlContent,
      });
      console.log(`✅ 已发送给: ${emailTo}`);
    } catch (err) {
      console.error(`❌ 发送给 ${emailTo} 失败:`, err);
    }
  }
}

checkAndSend();