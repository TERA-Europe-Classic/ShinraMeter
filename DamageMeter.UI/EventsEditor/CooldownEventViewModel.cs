using Data.Actions;
using Data.Events;
using System.Collections.Generic;

namespace DamageMeter.UI
{
    public class CooldownEventViewModel : BaseEventViewModel
    {
        private readonly CooldownEvent _event;
        private int _skillId;
        private bool _resetOnly;

        public int SkillId
        {
            get => _skillId;
            set
            {
                if (_skillId == value) return;
                _skillId = value;
                _event.SkillId = value;
                NotifyPropertyChanged();
                NotifyPropertyChanged(nameof(Summary));
                NotifyPropertyChanged(nameof(SearchText));
            }
        }

        public bool ResetOnly
        {
            get => _resetOnly;
            set
            {
                if (_resetOnly == value) return;
                _resetOnly = value;
                _event.OnlyResetted = value;
                NotifyPropertyChanged();
                NotifyPropertyChanged(nameof(Summary));
                NotifyPropertyChanged(nameof(SearchText));
            }
        }

        public override string Type => "Cooldown event";
        public override string Summary => ResetOnly ? $"Skill {SkillId} reset" : $"Skill {SkillId} cooldown";
        public override string SearchText => $"{base.SearchText} skill {SkillId} cooldown reset {ResetOnly}";

        public CooldownEventViewModel(CooldownEvent ev, List<Action> act) : base(ev, act)
        {
            _event = ev;
            _skillId = ev.SkillId;
            _resetOnly = ev.OnlyResetted;
        }
    }
}
